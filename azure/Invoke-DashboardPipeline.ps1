<#
.SYNOPSIS
    Unified Azure Automation runbook for the Defender vulnerability dashboard pipeline.

.DESCRIPTION
    This runbook performs the complete dashboard pipeline in a single execution:
    
    1. Authenticates via Managed Identity
    2. Downloads historical export data and templates from Azure Blob Storage
    3. Exports fresh vulnerability, machine, and Advanced Hunting data from MDE APIs
    4. Generates the self-contained HTML dashboard
    5. Uploads results back to Blob Storage (compressed)
    
    All data processing logic is inlined from Generate-VulnerabilityDashboard.ps1 to make
    the runbook fully self-contained with no external script dependencies.
    
    Export files are stored as .json.gz (GZip compressed) in blob storage to minimize
    storage costs and download bandwidth. They are decompressed in the ephemeral sandbox
    for processing and recompressed before upload.

.PARAMETER StorageAccountName
    Name of the Azure Storage account containing the exports, templates, and dashboards containers.
    If not provided, reads from the 'StorageAccountName' Automation variable.

.PARAMETER IncludeAdvancedHunting
    Include Advanced Hunting data for CVE enrichment (PublishedDate, Description, EPSS).
    Requires AdvancedQuery.Read.All permission on the Managed Identity. Default: true

.PARAMETER CompressData
    Compress embedded dashboard data with gzip for smaller HTML file size.

.PARAMETER Export
    Export target for the generated dashboard. Default: BlobStorage
    Options: BlobStorage, SharePoint, StaticWebApp

.NOTES
    Author: Nathan McNulty
    Runtime: PowerShell 7.4 (Azure Automation - custom runtime environment)
    
    Prerequisites:
    - System-assigned Managed Identity with:
      - Storage Blob Data Contributor on the Storage Account
      - MDE app roles: Machine.Read.All, Vulnerability.Read.All, AdvancedQuery.Read.All
    - Templates uploaded to the 'templates' blob container via Upload-Templates.ps1
#>

#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$StorageAccountName,

    [Parameter(Mandatory = $false)]
    [bool]$IncludeAdvancedHunting = $true,

    [Parameter(Mandatory = $false)]
    [switch]$CompressData,

    [Parameter(Mandatory = $false)]
    [ValidateSet('BlobStorage', 'SharePoint', 'StaticWebApp')]
    [string]$Export = 'BlobStorage'
)

$ErrorActionPreference = 'Stop'

# =============================================================================
# CONSTANTS
# =============================================================================

$Script:MdeApiUrl = 'https://api.securitycenter.microsoft.com'
$Script:MdeBulkExportUrl = 'https://api.security.microsoft.com/api/machines/SoftwareVulnerabilitiesExport'
$Script:AdvancedHuntingUrl = 'https://api.security.microsoft.com/api/advancedqueries/run'
$Script:BlobApiVersion = '2021-12-02'

$Script:BlobContainers = @{
    Exports    = 'exports'
    Templates  = 'templates'
    Dashboards = 'dashboards'
}

$Script:BlobAccessTiers = @{
    Exports    = 'Cold'
    Templates  = 'Cool'
    Dashboards = 'Hot'
}

$Script:LibraryConfig = @{
    ChartJs = @{
        Url = "https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.js"
        Name = "Chart.js"
        Critical = $true
    }
    PdfMake = @{
        Url = "https://cdnjs.cloudflare.com/ajax/libs/pdfmake/0.2.7/pdfmake.min.js"
        Name = "pdfmake"
        Critical = $false
    }
    VfsFonts = @{
        Url = "https://cdnjs.cloudflare.com/ajax/libs/pdfmake/0.2.7/vfs_fonts.min.js"
        Name = "vfs_fonts"
        Critical = $false
    }
    Html2Pdf = @{
        Url = "https://cdn.jsdelivr.net/npm/html2pdf.js@0.10.1/dist/html2pdf.bundle.min.js"
        Name = "html2pdf.js"
        Critical = $false
    }
    Html2Canvas = @{
        Url = "https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js"
        Name = "html2canvas"
        Critical = $false
    }
    Pako = @{
        Url = "https://cdn.jsdelivr.net/npm/pako@2.1.0/dist/pako.min.js"
        Name = "pako"
        Critical = $false
    }
}

# =============================================================================
# HELPER FUNCTIONS - TOKEN MANAGEMENT
# =============================================================================

function Get-PlainToken {
    <#
    .SYNOPSIS
        Gets a plain-text bearer token using Get-AzAccessToken -AsSecureString.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ResourceUrl
    )

    $tokenResponse = Get-AzAccessToken -ResourceUrl $ResourceUrl -AsSecureString
    $ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($tokenResponse.Token)
    try { return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr) }
    finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr) }
}

# =============================================================================
# HELPER FUNCTIONS - GZIP COMPRESSION
# =============================================================================

function Compress-GzipFile {
    <#
    .SYNOPSIS
        Compresses a file with GZip. Input: file path → Output: .gz file path.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$InputPath,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    $inputStream = $null
    $outputStream = $null
    $gzipStream = $null
    try {
        $inputStream = [System.IO.File]::OpenRead($InputPath)
        $outputStream = [System.IO.File]::Create($OutputPath)
        $gzipStream = [System.IO.Compression.GZipStream]::new(
            $outputStream, [System.IO.Compression.CompressionLevel]::Optimal
        )
        $inputStream.CopyTo($gzipStream)
    }
    finally {
        if ($gzipStream) { $gzipStream.Dispose() }
        if ($outputStream) { $outputStream.Dispose() }
        if ($inputStream) { $inputStream.Dispose() }
    }
}

function Expand-GzipFile {
    <#
    .SYNOPSIS
        Decompresses a GZip file. Input: .gz file path → Output: decompressed file path.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$InputPath,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    $inputStream = $null
    $gzipStream = $null
    $outputStream = $null
    try {
        $inputStream = [System.IO.File]::OpenRead($InputPath)
        $gzipStream = [System.IO.Compression.GZipStream]::new(
            $inputStream, [System.IO.Compression.CompressionMode]::Decompress
        )
        $outputStream = [System.IO.File]::Create($OutputPath)
        $gzipStream.CopyTo($outputStream)
    }
    finally {
        if ($outputStream) { $outputStream.Dispose() }
        if ($gzipStream) { $gzipStream.Dispose() }
        if ($inputStream) { $inputStream.Dispose() }
    }
}

function Test-GzipSupport {
    <#
    .SYNOPSIS
        Tests if GZip compression/decompression works in the current runtime.
    #>
    try {
        $testBytes = [System.Text.Encoding]::UTF8.GetBytes("GZip test data")
        $memStream = [System.IO.MemoryStream]::new()
        $gzipStream = [System.IO.Compression.GZipStream]::new(
            $memStream, [System.IO.Compression.CompressionMode]::Compress
        )
        $gzipStream.Write($testBytes, 0, $testBytes.Length)
        $gzipStream.Dispose()
        $compressed = $memStream.ToArray()
        $memStream.Dispose()

        # Decompress
        $memStream2 = [System.IO.MemoryStream]::new($compressed)
        $gzipStream2 = [System.IO.Compression.GZipStream]::new(
            $memStream2, [System.IO.Compression.CompressionMode]::Decompress
        )
        $resultStream = [System.IO.MemoryStream]::new()
        $gzipStream2.CopyTo($resultStream)
        $gzipStream2.Dispose()
        $memStream2.Dispose()
        $result = [System.Text.Encoding]::UTF8.GetString($resultStream.ToArray())
        $resultStream.Dispose()

        return ($result -eq "GZip test data")
    }
    catch {
        return $false
    }
}

# =============================================================================
# HELPER FUNCTIONS - BLOB STORAGE REST API
# =============================================================================

function Get-BlobHeaders {
    <#
    .SYNOPSIS
        Returns standard headers for Blob REST API calls.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$StorageToken
    )

    return @{
        'Authorization'  = "Bearer $StorageToken"
        'x-ms-version'   = $Script:BlobApiVersion
    }
}

function Get-BlobList {
    <#
    .SYNOPSIS
        Lists all blobs in a container.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccountName,

        [Parameter(Mandatory)]
        [string]$Container,

        [Parameter(Mandatory)]
        [string]$StorageToken,

        [string]$Prefix
    )

    $baseUrl = "https://$AccountName.blob.core.windows.net"
    $uri = "$baseUrl/$Container`?restype=container&comp=list"
    if ($Prefix) { $uri += "&prefix=$Prefix" }

    $headers = Get-BlobHeaders -StorageToken $StorageToken

    try {
        $webResponse = Invoke-WebRequest -Uri $uri -Headers $headers -Method Get -UseBasicParsing
        $xmlContent = $webResponse.Content.TrimStart([char]0xFEFF)
        $xmlDoc = [System.Xml.XmlDocument]::new()
        $xmlDoc.LoadXml($xmlContent)
        $blobs = $xmlDoc.EnumerationResults.Blobs.Blob
        if ($null -eq $blobs) { return @() }
        return @($blobs | ForEach-Object { $_.Name })
    }
    catch {
        if ($_.Exception.Response.StatusCode -eq 404) { return @() }
        throw "Failed to list blobs in '$Container': $_"
    }
}

function Get-BlobContent {
    <#
    .SYNOPSIS
        Downloads a blob to a local file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccountName,

        [Parameter(Mandatory)]
        [string]$Container,

        [Parameter(Mandatory)]
        [string]$BlobName,

        [Parameter(Mandatory)]
        [string]$DestinationPath,

        [Parameter(Mandatory)]
        [string]$StorageToken
    )

    $baseUrl = "https://$AccountName.blob.core.windows.net"
    $uri = "$baseUrl/$Container/$BlobName"
    $headers = Get-BlobHeaders -StorageToken $StorageToken

    $parentDir = Split-Path -Path $DestinationPath -Parent
    if (-not (Test-Path $parentDir)) { New-Item -Path $parentDir -ItemType Directory -Force | Out-Null }

    Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -OutFile $DestinationPath
}

function Set-BlobContent {
    <#
    .SYNOPSIS
        Uploads a local file as a block blob.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccountName,

        [Parameter(Mandatory)]
        [string]$Container,

        [Parameter(Mandatory)]
        [string]$BlobName,

        [Parameter(Mandatory)]
        [string]$SourcePath,

        [Parameter(Mandatory)]
        [string]$StorageToken,

        [string]$ContentType = 'application/octet-stream',

        [ValidateSet('Hot','Cool','Cold','Archive')]
        [string]$AccessTier
    )

    $baseUrl = "https://$AccountName.blob.core.windows.net"
    $uri = "$baseUrl/$Container/$BlobName"
    $headers = Get-BlobHeaders -StorageToken $StorageToken
    $headers['x-ms-blob-type'] = 'BlockBlob'
    if ($AccessTier) { $headers['x-ms-access-tier'] = $AccessTier }

    Invoke-RestMethod -Uri $uri -Method Put -Headers $headers -InFile $SourcePath -ContentType $ContentType
}

function Test-BlobExists {
    <#
    .SYNOPSIS
        Checks if a blob exists. Returns $true/$false.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccountName,

        [Parameter(Mandatory)]
        [string]$Container,

        [Parameter(Mandatory)]
        [string]$BlobName,

        [Parameter(Mandatory)]
        [string]$StorageToken
    )

    $baseUrl = "https://$AccountName.blob.core.windows.net"
    $uri = "$baseUrl/$Container/$BlobName"
    $headers = Get-BlobHeaders -StorageToken $StorageToken

    try {
        Invoke-WebRequest -Uri $uri -Headers $headers -Method Head -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

# =============================================================================
# HELPER FUNCTIONS - MDE API
# =============================================================================

function Get-MdeHeaders {
    <#
    .SYNOPSIS
        Returns standard headers for MDE API calls.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$MdeToken
    )

    return @{
        'Authorization' = "Bearer $MdeToken"
        'Content-Type'  = 'application/json'
        'Accept'        = 'application/json'
    }
}

function Export-BulkVulnerabilities {
    <#
    .SYNOPSIS
        Downloads bulk vulnerability export files from the MDE API.
    .DESCRIPTION
        Calls the SoftwareVulnerabilitiesExport endpoint which returns pre-signed
        URLs to .json.gz files. Downloads and decompresses each file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Headers,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    Write-Output "Requesting bulk vulnerability export..."
    $response = Invoke-RestMethod -Uri $Script:MdeBulkExportUrl -Headers $Headers -Method Get

    if (-not $response.exportFiles -or $response.exportFiles.Count -eq 0) {
        Write-Warning "Bulk vulnerability export returned no files."
        return
    }

    Write-Output "  Downloading $($response.exportFiles.Count) export file(s)..."

    foreach ($fileUrl in $response.exportFiles) {
        # Parse URL to derive filename (matching GitHub Actions workflow pattern)
        # Expected format: https://winatp-gw-{region}.microsoft.com/api/machines/SoftwareVulnerabilitiesExport/collection/{date}/files/{index}?...%3DgroupId%3D{id}
        $urlParts = $fileUrl.Split('/')
        $date = $urlParts[6]
        $groupId = $urlParts[9].Split('%3D')[-1]
        $gzFile = Join-Path -Path $OutputPath -ChildPath "VulnExport_${groupId}_${date}.json.gz"
        $jsonFile = Join-Path -Path $OutputPath -ChildPath "VulnExport_${groupId}_${date}.json"

        Write-Output "  Downloading VulnExport_${groupId}_${date}..."
        Invoke-WebRequest -Uri $fileUrl -OutFile $gzFile

        # Decompress
        Write-Output "  Decompressing..."
        Expand-GzipFile -InputPath $gzFile -OutputPath $jsonFile
        Remove-Item -Path $gzFile -Force

        Write-Output "  Saved: $(Split-Path -Leaf $jsonFile)"
    }
}

function Export-MachineData {
    <#
    .SYNOPSIS
        Exports machine data from the MDE /api/machines endpoint (paginated).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Headers,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    Write-Host "Exporting machine data from MDE API..."

    $allMachines = [System.Collections.Generic.List[PSObject]]::new()
    $uri = "$($Script:MdeApiUrl)/api/machines?`$filter=onboardingStatus eq 'Onboarded'"
    $pageCount = 0

    do {
        $pageCount++
        Write-Host "  Fetching page $pageCount..."
        $response = Invoke-RestMethod -Uri $uri -Headers $Headers -Method Get

        if ($response.value) {
            foreach ($machine in $response.value) {
                $allMachines.Add($machine)
            }
        }

        $uri = if ($response.PSObject.Properties['@odata.nextLink']) {
            $response.'@odata.nextLink'
        } else { $null }
    } while ($uri)

    Write-Host "  Total machines: $($allMachines.Count)"

    $timestamp = Get-Date -Format "yyyy-MM-dd"
    $outputFile = Join-Path -Path $OutputPath -ChildPath "Machines_$timestamp.json"
    $allMachines | ConvertTo-Json -Depth 10 | Out-File -FilePath $outputFile -Encoding UTF8

    Write-Host "  Saved: $(Split-Path -Leaf $outputFile)"
    return $outputFile
}

function Export-AdvancedHuntingData {
    <#
    .SYNOPSIS
        Exports Advanced Hunting data for CVE enrichment.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Headers,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    Write-Host "Exporting Advanced Hunting data..."

    $query = @"
DeviceTvmSoftwareVulnerabilities
| join kind=leftouter DeviceTvmSoftwareVulnerabilitiesKB on CveId
| project DeviceId, CveId, PublishedDate, VulnerabilityDescription, IsExploitAvailable, EpssScore, LastModifiedTime, AffectedSoftware
"@

    $body = @{ Query = $query } | ConvertTo-Json

    $response = Invoke-RestMethod -Uri $Script:AdvancedHuntingUrl -Headers $Headers -Method Post -Body $body

    if (-not $response.Results -or $response.Results.Count -eq 0) {
        Write-Warning "Advanced Hunting query returned no results."
        return $null
    }

    $resultCount = $response.Results.Count
    Write-Host "  Retrieved $resultCount records"

    $timestamp = Get-Date -Format "yyyy-MM-dd"
    $outputFile = Join-Path -Path $OutputPath -ChildPath "AdvancedHunting_${resultCount}_$timestamp.json"

    $ndjsonLines = $response.Results | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 10 }
    $ndjsonLines -join "`n" | Out-File -FilePath $outputFile -Encoding UTF8 -NoNewline

    Write-Host "  Saved: $(Split-Path -Leaf $outputFile)"
    return $outputFile
}

# =============================================================================
# HELPER FUNCTIONS - DATA PROCESSING (from Generate-VulnerabilityDashboard.ps1)
# =============================================================================

function Read-MachineData {
    <#
    .SYNOPSIS
        Reads and merges machine data from Machines_*.json files, deduplicating by machine ID.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    Write-Host "Reading machine data from $Path..."

    $machineFiles = @(Get-ChildItem -Path $Path -Filter "Machines_*.json" -File | Sort-Object Name -Descending)

    if ($machineFiles.Count -eq 0) {
        Write-Warning "No machine data files found."
        return @{}
    }

    Write-Host "  Found $($machineFiles.Count) machine data file(s)"
    $machines = @{}

    foreach ($file in $machineFiles) {
        Write-Host "  Processing $($file.Name)..."
        $content = Get-Content -Path $file.FullName -Raw
        $machineList = $content | ConvertFrom-Json
        if ($null -eq $machineList) { continue }
        if ($machineList -isnot [System.Array]) { $machineList = @($machineList) }

        foreach ($machine in $machineList) {
            if ($null -eq $machine) { continue }
            $id = $machine.id
            if ($id -and -not $machines.ContainsKey($id)) { $machines[$id] = $machine }
        }
    }

    Write-Host "  Loaded $($machines.Count) unique machines"
    return $machines
}

function Read-VulnerabilityData {
    <#
    .SYNOPSIS
        Reads VulnExport_*.json files (NDJSON format), returns list of vulnerability objects.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    Write-Host "Reading vulnerability data from $Path..."

    $jsonFiles = Get-ChildItem -Path $Path -Filter "VulnExport_*.json" -File |
        Where-Object { $_.Name -notmatch '_enriched\.json$' }

    if ($jsonFiles.Count -eq 0) {
        throw "No VulnExport JSON files found in '$Path'."
    }

    Write-Host "  Found $($jsonFiles.Count) file(s)"
    $vulnerabilities = [System.Collections.Generic.List[PSObject]]::new()
    $parseErrors = 0

    foreach ($file in $jsonFiles) {
        Write-Host "  Processing $($file.Name)..."
        $content = Get-Content -Path $file.FullName -Raw
        $lines = $content -split "`n" | Where-Object { $_.Trim() -ne "" }

        foreach ($line in $lines) {
            try {
                $vuln = $line | ConvertFrom-Json
                $vulnerabilities.Add($vuln)
            }
            catch {
                $parseErrors++
                if ($parseErrors -le 5) { Write-Warning "Parse error in $($file.Name): $_" }
            }
        }
    }

    if ($parseErrors -gt 0) { Write-Host "  Parse errors: $parseErrors" }
    Write-Host "  Total vulnerabilities loaded: $($vulnerabilities.Count)"
    return $vulnerabilities
}

function Read-AdvancedHuntingData {
    <#
    .SYNOPSIS
        Reads AdvancedHunting_*.json files, deduplicates by CveId, returns hashtable.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    Write-Host "Reading Advanced Hunting data from $Path..."

    $ahFiles = @(Get-ChildItem -Path $Path -Filter "AdvancedHunting_*.json" -File | Sort-Object Name -Descending)

    if ($ahFiles.Count -eq 0) {
        Write-Host "  No Advanced Hunting files found. CVE enrichment skipped."
        return @{}
    }

    Write-Host "  Found $($ahFiles.Count) file(s)"
    $ahData = @{}
    $parseErrors = 0

    foreach ($file in $ahFiles) {
        Write-Host "  Processing $($file.Name)..."
        $content = Get-Content -Path $file.FullName -Raw
        $lines = $content -split "`n" | Where-Object { $_.Trim() -ne "" }

        foreach ($line in $lines) {
            try {
                $record = $line | ConvertFrom-Json
                $cveId = $record.CveId
                if ($cveId -and -not $ahData.ContainsKey($cveId)) {
                    $pdRaw = $record.PSObject.Properties['PublishedDate']?.Value
                    $ahData[$cveId] = @{
                        PublishedDate            = if ($pdRaw) { ($pdRaw.ToString() -split '[T ]')[0] } else { $null }
                        VulnerabilityDescription = $record.PSObject.Properties['VulnerabilityDescription']?.Value
                        EpssScore                = $record.PSObject.Properties['EpssScore']?.Value
                    }
                }
            }
            catch {
                $parseErrors++
                if ($parseErrors -le 5) { Write-Warning "Parse error in $($file.Name): $_" }
            }
        }
    }

    Write-Host "  Loaded enrichment data for $($ahData.Count) unique CVEs"
    return $ahData
}

function ConvertTo-NormalizedData {
    <#
    .SYNOPSIS
        Normalizes vulnerability data into compact lookup tables and indexed records.
    .DESCRIPTION
        Transforms raw vulnerability data into a normalized structure with:
        - Lookup tables for repeated strings (vendors, software, CVEs, etc.)
        - Compact vulnerability records using indices instead of strings
        - Machine data merged from separate source
        - Advanced Hunting enrichment (PublishedDate, VulnerabilityDescription, EpssScore)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.Generic.List[PSObject]]$Vulnerabilities,

        [Parameter(Mandatory)]
        [hashtable]$Machines,

        [Parameter(Mandatory = $false)]
        [hashtable]$AdvancedHuntingData = @{}
    )

    Write-Host "  Normalizing data structure..."

    # Initialize lookup tables
    $lookups = @{
        vendors       = [System.Collections.Generic.List[string]]::new()
        severities    = @('Critical', 'High', 'Medium', 'Low')
        exploitLevels = [System.Collections.Generic.List[string]]::new()
        groups        = [System.Collections.Generic.List[string]]::new()
        platforms     = [System.Collections.Generic.List[string]]::new()
        tags          = [System.Collections.Generic.List[string]]::new()
        updates       = [System.Collections.Generic.List[PSObject]]::new()
        devices       = [System.Collections.Generic.List[PSObject]]::new()
        software      = [System.Collections.Generic.List[PSObject]]::new()
        cves          = [System.Collections.Generic.List[PSObject]]::new()
    }

    # Index maps for O(1) lookup
    $vendorIndex = @{}
    $exploitIndex = @{}
    $groupIndex = @{}
    $platformIndex = @{}
    $tagIndex = @{}
    $updateIndex = @{}
    $deviceIndex = @{}
    $softwareIndex = @{}
    $cveIndex = @{}

    function Get-OrCreateIndex {
        param($value, $list, $indexMap)
        if ($null -eq $value -or $value -eq '') { return -1 }
        $key = $value.ToString()
        if (-not $indexMap.ContainsKey($key)) {
            $indexMap[$key] = $list.Count
            $list.Add($key)
        }
        return $indexMap[$key]
    }

    $vulnRecords = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($v in $Vulnerabilities) {
        $deviceId = $v.DeviceId
        if (-not $deviceIndex.ContainsKey($deviceId)) {
            $machine = $Machines[$deviceId]

            $groupName = if ($machine) { $machine.PSObject.Properties['rbacGroupName']?.Value } else { $v.PSObject.Properties['RbacGroupName']?.Value }
            $groupIdx = Get-OrCreateIndex -value $groupName -list $lookups.groups -indexMap $groupIndex

            $osPlat = if ($machine) { $machine.PSObject.Properties['osPlatform']?.Value } else { $v.PSObject.Properties['OSPlatform']?.Value }
            $platIdx = Get-OrCreateIndex -value $osPlat -list $lookups.platforms -indexMap $platformIndex

            $machineTags = if ($machine -and $machine.PSObject.Properties['machineTags']?.Value) { $machine.machineTags }
                          elseif ($v.PSObject.Properties['MachineTags']?.Value) { $v.PSObject.Properties['MachineTags']?.Value }
                          else { @() }
            $tagIndices = [System.Collections.Generic.List[int]]::new()
            foreach ($tag in $machineTags) {
                $tagIdx = Get-OrCreateIndex -value $tag -list $lookups.tags -indexMap $tagIndex
                if ($tagIdx -ge 0) { $tagIndices.Add($tagIdx) }
            }

            $deviceIndex[$deviceId] = $lookups.devices.Count

            $machineInfo = $null
            if ($machine) {
                $machineLastSeen = $machine.PSObject.Properties['lastSeen']?.Value
                $machineFirstSeen = $machine.PSObject.Properties['firstSeen']?.Value
                $machineInfo = [PSCustomObject]@{
                    ip  = $machine.PSObject.Properties['lastIpAddress']?.Value
                    eip = $machine.PSObject.Properties['lastExternalIpAddress']?.Value
                    hs  = $machine.PSObject.Properties['healthStatus']?.Value
                    rs  = $machine.PSObject.Properties['riskScore']?.Value
                    el  = $machine.PSObject.Properties['exposureLevel']?.Value
                    dv  = $machine.PSObject.Properties['deviceValue']?.Value
                    mb  = $machine.PSObject.Properties['managedBy']?.Value
                    aad = $machine.PSObject.Properties['isAadJoined']?.Value
                    ls  = if ($machineLastSeen) { ($machineLastSeen -split 'T')[0] } else { $null }
                    fs  = if ($machineFirstSeen) { ($machineFirstSeen -split 'T')[0] } else { $null }
                }
            }

            $lookups.devices.Add([PSCustomObject]@{
                id = $deviceId
                n  = if ($machine) { $machine.PSObject.Properties['computerDnsName']?.Value } elseif ($v.PSObject.Properties['DeviceName']?.Value) { $v.PSObject.Properties['DeviceName']?.Value } else { "(no machine data)" }
                g  = $groupIdx
                o  = $platIdx
                ov = if ($machine) { $machine.PSObject.Properties['osVersion']?.Value } else { $v.PSObject.Properties['OSVersion']?.Value }
                t  = $tagIndices
                m  = $machineInfo
            })
        }
        $devIdx = $deviceIndex[$deviceId]

        $vendorIdx = Get-OrCreateIndex -value $v.PSObject.Properties['SoftwareVendor']?.Value -list $lookups.vendors -indexMap $vendorIndex

        $softwareVendor = $v.PSObject.Properties['SoftwareVendor']?.Value ?? ''
        $softwareName = $v.PSObject.Properties['SoftwareName']?.Value ?? ''
        $softwareKey = "$softwareVendor|$softwareName"
        if (-not $softwareIndex.ContainsKey($softwareKey)) {
            $softwareIndex[$softwareKey] = $lookups.software.Count
            $lookups.software.Add([PSCustomObject]@{
                v = $vendorIdx
                n = $softwareName
                r = $v.PSObject.Properties['RecommendationReference']?.Value
            })
        }
        $swIdx = $softwareIndex[$softwareKey]

        $cveId = $v.CveId
        if (-not $cveIndex.ContainsKey($cveId)) {
            $sevLevel = $v.PSObject.Properties['VulnerabilitySeverityLevel']?.Value
            $sevIdx = switch ($sevLevel) {
                'Critical' { 0 }
                'High' { 1 }
                'Medium' { 2 }
                'Low' { 3 }
                default { -1 }
            }

            $expIdx = Get-OrCreateIndex -value $v.PSObject.Properties['ExploitabilityLevel']?.Value -list $lookups.exploitLevels -indexMap $exploitIndex

            $ahData = $AdvancedHuntingData[$cveId]
            $publishedDate = $null
            $vulnDescription = $null
            $epssScore = $null
            if ($ahData) {
                $pdRaw = $ahData.PublishedDate
                $publishedDate = if ($pdRaw) { ($pdRaw -split 'T')[0] } else { $null }
                $vulnDescription = $ahData.VulnerabilityDescription
                $epssScore = $ahData.EpssScore
            }

            $cveIndex[$cveId] = $lookups.cves.Count
            $lookups.cves.Add([PSCustomObject]@{
                id   = $cveId
                sc   = $v.PSObject.Properties['CvssScore']?.Value
                sv   = $sevIdx
                ex   = $expIdx
                u    = $v.PSObject.Properties['CveBatchUrl']?.Value
                bt   = $v.PSObject.Properties['CveBatchTitle']?.Value
                pd   = $publishedDate
                desc = $vulnDescription
                ep   = $epssScore
            })
        }
        $cveIdx = $cveIndex[$cveId]

        # Get or create update index (stores object with name, id, url)
        $recUpdate = $v.PSObject.Properties['RecommendedSecurityUpdate']?.Value
        $updateName = if ($recUpdate -and $recUpdate -ne '--') { $recUpdate } else { $null }
        if ($null -eq $updateName -or $updateName -eq '') {
            $updIdx = -1
        } elseif ($updateIndex.ContainsKey($updateName)) {
            $updIdx = $updateIndex[$updateName]
        } else {
            $updIdx = $lookups.updates.Count
            $updateIndex[$updateName] = $updIdx
            $lookups.updates.Add([PSCustomObject]@{
                n   = $updateName
                id  = $v.PSObject.Properties['RecommendedSecurityUpdateId']?.Value
                url = $v.PSObject.Properties['RecommendedSecurityUpdateUrl']?.Value
            })
        }

        $firstSeenTs = $v.PSObject.Properties['FirstSeenTimestamp']?.Value
        $lastSeenTs = $v.PSObject.Properties['LastSeenTimestamp']?.Value
        $firstSeen = if ($firstSeenTs) { ($firstSeenTs -split ' ')[0] } else { '' }
        $lastSeen = if ($lastSeenTs) { ($lastSeenTs -split ' ')[0] } else { '' }

        $diskPaths = $v.PSObject.Properties['DiskPaths']?.Value
        $regPaths = $v.PSObject.Properties['RegistryPaths']?.Value

        $secUpdateAvail = $v.PSObject.Properties['SecurityUpdateAvailable']?.Value
        $vulnRecords.Add(@(
            $devIdx,
            $cveIdx,
            $swIdx,
            $v.PSObject.Properties['SoftwareVersion']?.Value,
            $firstSeen,
            $lastSeen,
            [int]($secUpdateAvail -eq $true),
            $updIdx,
            $diskPaths,
            $regPaths
        ))
    }

    # Handle "(No Tags)" label
    $noTagsLabel = "(No Tags)"
    $hasNoTags = $lookups.devices | Where-Object { $_.t.Count -eq 0 }
    if ($hasNoTags -and -not $tagIndex.ContainsKey($noTagsLabel)) {
        $tagIndex[$noTagsLabel] = $lookups.tags.Count
        $lookups.tags.Add($noTagsLabel)
    }
    $noTagsIdx = if ($tagIndex.ContainsKey($noTagsLabel)) { $tagIndex[$noTagsLabel] } else { -1 }

    Write-Host "  Normalized: $($lookups.devices.Count) devices, $($lookups.cves.Count) CVEs, $($lookups.software.Count) software"

    return @{
        Lookups = [PSCustomObject]@{
            vendors       = $lookups.vendors
            severities    = $lookups.severities
            exploitLevels = $lookups.exploitLevels
            groups        = $lookups.groups
            platforms     = $lookups.platforms
            tags          = $lookups.tags
            updates       = $lookups.updates
            devices       = $lookups.devices
            software      = $lookups.software
            cves          = $lookups.cves
            noTagsIdx     = $noTagsIdx
        }
        Vulns = $vulnRecords
    }
}

function Get-JSLibrary {
    <#
    .SYNOPSIS
        Downloads a JavaScript library from a CDN URL with error handling.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Url,

        [Parameter(Mandatory)]
        [string]$Name,

        [bool]$Critical = $false
    )

    Write-Host "  Downloading $Name..."
    try {
        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 30
        return $response.Content
    }
    catch {
        if ($Critical) { throw "Failed to download critical library $Name from $Url`: $_" }
        Write-Warning "Failed to download $Name from $Url`: $_"
        return "// $Name failed to load - functionality may be limited"
    }
}

# =============================================================================
# HELPER FUNCTIONS - EXPORT TARGETS
# =============================================================================

function Export-ToBlobStorage {
    <#
    .SYNOPSIS
        Uploads new export files (compressed) and dashboard HTML to blob storage.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccountName,

        [Parameter(Mandatory)]
        [string]$StorageToken,

        [Parameter(Mandatory)]
        [string]$ExportsPath,

        [Parameter(Mandatory)]
        [string]$DashboardPath,

        [bool]$UseGzip = $true
    )

    Write-Output "`nUploading results to blob storage..."

    # Upload new export files (compressed)
    $exportFiles = Get-ChildItem -Path $ExportsPath -Filter "*.json" -File
    foreach ($file in $exportFiles) {
        if ($UseGzip) {
            $gzPath = "$($file.FullName).gz"
            $blobName = "$($file.Name).gz"

            # Skip if this blob already exists
            if (Test-BlobExists -AccountName $AccountName -Container $Script:BlobContainers.Exports -BlobName $blobName -StorageToken $StorageToken) {
                Write-Output "  Skipping $blobName (already exists)"
                continue
            }

            Write-Output "  Compressing and uploading $($file.Name)..."
            Compress-GzipFile -InputPath $file.FullName -OutputPath $gzPath
            $originalSize = (Get-Item $file.FullName).Length
            $compressedSize = (Get-Item $gzPath).Length
            $ratio = if ($originalSize -gt 0) { [math]::Round((1 - $compressedSize / $originalSize) * 100, 1) } else { 0 }
            Write-Output "    Compressed: $([math]::Round($originalSize/1KB))KB -> $([math]::Round($compressedSize/1KB))KB ($ratio% reduction)"

            Set-BlobContent -AccountName $AccountName -Container $Script:BlobContainers.Exports -BlobName $blobName -SourcePath $gzPath -StorageToken $StorageToken -ContentType 'application/gzip' -AccessTier $Script:BlobAccessTiers.Exports
            Remove-Item -Path $gzPath -Force
        }
        else {
            $blobName = $file.Name
            if (Test-BlobExists -AccountName $AccountName -Container $Script:BlobContainers.Exports -BlobName $blobName -StorageToken $StorageToken) {
                Write-Output "  Skipping $blobName (already exists)"
                continue
            }
            Write-Output "  Uploading $($file.Name)..."
            Set-BlobContent -AccountName $AccountName -Container $Script:BlobContainers.Exports -BlobName $blobName -SourcePath $file.FullName -StorageToken $StorageToken -ContentType 'application/json' -AccessTier $Script:BlobAccessTiers.Exports
        }
    }

    # Upload dashboard HTML (always uncompressed)
    if (Test-Path $DashboardPath) {
        Write-Output "  Uploading VulnerabilityDashboard.html..."
        Set-BlobContent -AccountName $AccountName -Container $Script:BlobContainers.Dashboards -BlobName "VulnerabilityDashboard.html" -SourcePath $DashboardPath -StorageToken $StorageToken -ContentType 'text/html' -AccessTier $Script:BlobAccessTiers.Dashboards
        Write-Output "  Dashboard uploaded to '$($Script:BlobContainers.Dashboards)/VulnerabilityDashboard.html'"
    }
}

function Export-ToSharePoint {
    <#
    .SYNOPSIS
        Uploads dashboard to SharePoint Online. (Not yet implemented)
    #>
    [CmdletBinding()]
    param(
        [string]$DashboardPath
    )

    Write-Warning "SharePoint export is not yet implemented."
    Write-Output "  To implement: Upload via Microsoft Graph API using Sites.ReadWrite.All permission."
    Write-Output "  The Managed Identity would need the Sites.ReadWrite.All app role on the Microsoft Graph SP."
}

function Export-ToStaticWebApp {
    <#
    .SYNOPSIS
        Deploys dashboard to Azure Static Web Apps. (Not yet implemented)
    #>
    [CmdletBinding()]
    param(
        [string]$DashboardPath
    )

    Write-Warning "Static Web App export is not yet implemented."
    Write-Output "  To implement: Use the SWA CLI (swa deploy) with a deployment token."
    Write-Output "  Note: Azure Automation sandboxes do not have Node.js; consider a Hybrid Runbook Worker."
}

# =============================================================================
# MAIN PIPELINE
# =============================================================================

try {
    Write-Output "========================================"
    Write-Output "  Vulnerability Dashboard Pipeline"
    Write-Output "========================================"
    Write-Output "  Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') UTC"

    # -----------------------------------------------------------------
    # Stage A: Authenticate
    # -----------------------------------------------------------------
    Write-Output "`n--- Stage A: Authentication ---"

    Write-Output "Connecting with Managed Identity..."
    Connect-AzAccount -Identity | Out-Null
    Write-Output "  Connected successfully"

    # Resolve StorageAccountName from Automation variable if not provided as parameter
    if (-not $StorageAccountName) {
        Write-Output "  Reading StorageAccountName from Automation variable..."
        $StorageAccountName = Get-AutomationVariable -Name 'StorageAccountName'
        if (-not $StorageAccountName) {
            throw "StorageAccountName not provided and Automation variable not found."
        }
    }
    Write-Output "  Storage account: $StorageAccountName"

    Write-Output "  Acquiring tokens..."
    $storageToken = Get-PlainToken -ResourceUrl 'https://storage.azure.com/'
    $mdeToken = Get-PlainToken -ResourceUrl 'https://api.securitycenter.microsoft.com'
    $mdeHeaders = Get-MdeHeaders -MdeToken $mdeToken
    Write-Output "  Tokens acquired"

    # Test GZip support
    $useGzip = Test-GzipSupport
    if ($useGzip) {
        Write-Output "  GZip compression: supported"
    }
    else {
        Write-Warning "GZip compression not available in this runtime. Files will be stored uncompressed."
    }

    # -----------------------------------------------------------------
    # Stage B: Download historical data from blob storage
    # -----------------------------------------------------------------
    Write-Output "`n--- Stage B: Download historical data ---"

    $tempRoot = Join-Path -Path $env:TEMP -ChildPath "dashboard-pipeline-$(Get-Date -Format 'yyyyMMddHHmmss')"
    $tempExports = Join-Path -Path $tempRoot -ChildPath "exports"
    $tempTemplates = Join-Path -Path $tempRoot -ChildPath "templates"
    $tempDashboards = Join-Path -Path $tempRoot -ChildPath "dashboards"

    New-Item -Path $tempExports -ItemType Directory -Force | Out-Null
    New-Item -Path $tempTemplates -ItemType Directory -Force | Out-Null
    New-Item -Path $tempDashboards -ItemType Directory -Force | Out-Null

    # Download historical export files
    Write-Output "Downloading historical exports..."
    $existingBlobs = Get-BlobList -AccountName $StorageAccountName -Container $Script:BlobContainers.Exports -StorageToken $storageToken
    Write-Output "  Found $($existingBlobs.Count) existing blob(s)"

    foreach ($blobName in $existingBlobs) {
        $localFile = Join-Path -Path $tempExports -ChildPath $blobName
        Write-Output "  Downloading $blobName..."
        Get-BlobContent -AccountName $StorageAccountName -Container $Script:BlobContainers.Exports -BlobName $blobName -DestinationPath $localFile -StorageToken $storageToken

        # Decompress .gz files
        if ($blobName -match '\.json\.gz$') {
            $jsonFile = $localFile -replace '\.gz$', ''
            Write-Output "    Decompressing..."
            Expand-GzipFile -InputPath $localFile -OutputPath $jsonFile
            Remove-Item -Path $localFile -Force
        }
    }

    # Download templates
    Write-Output "Downloading templates..."
    $templateBlobs = Get-BlobList -AccountName $StorageAccountName -Container $Script:BlobContainers.Templates -StorageToken $storageToken

    if ($templateBlobs.Count -eq 0) {
        throw "No templates found in '$($Script:BlobContainers.Templates)' container. Run Upload-Templates.ps1 first."
    }

    foreach ($blobName in $templateBlobs) {
        $localFile = Join-Path -Path $tempTemplates -ChildPath $blobName
        Write-Output "  Downloading $blobName..."
        Get-BlobContent -AccountName $StorageAccountName -Container $Script:BlobContainers.Templates -BlobName $blobName -DestinationPath $localFile -StorageToken $storageToken
    }

    # -----------------------------------------------------------------
    # Stage C: Export fresh MDE data
    # -----------------------------------------------------------------
    Write-Output "`n--- Stage C: Export fresh MDE data ---"

    # Bulk vulnerability export
    Export-BulkVulnerabilities -Headers $mdeHeaders -OutputPath $tempExports

    # Machine data
    Export-MachineData -Headers $mdeHeaders -OutputPath $tempExports

    # Advanced Hunting (optional)
    if ($IncludeAdvancedHunting) {
        Export-AdvancedHuntingData -Headers $mdeHeaders -OutputPath $tempExports
    }
    else {
        Write-Output "Skipping Advanced Hunting export (IncludeAdvancedHunting = false)"
    }

    # -----------------------------------------------------------------
    # Stage D: Generate dashboard
    # -----------------------------------------------------------------
    Write-Output "`n--- Stage D: Generate dashboard ---"

    # Step 1: Read all data
    $machines = Read-MachineData -Path $tempExports
    $advancedHuntingData = Read-AdvancedHuntingData -Path $tempExports
    $allVulnerabilities = Read-VulnerabilityData -Path $tempExports

    # Step 2: Filter to onboarded devices
    $onboardedVulnerabilities = [System.Collections.Generic.List[PSObject]]::new()
    foreach ($vuln in $allVulnerabilities) {
        if ($vuln.PSObject.Properties['IsOnboarded']?.Value -eq $true) {
            $onboardedVulnerabilities.Add($vuln)
        }
    }
    Write-Output "  Filtered to onboarded: $($onboardedVulnerabilities.Count) vulnerabilities"

    if ($onboardedVulnerabilities.Count -eq 0) {
        throw "No vulnerabilities found for onboarded devices."
    }

    # Step 3: Download JavaScript libraries
    Write-Output "Downloading JavaScript libraries..."
    $lib = $Script:LibraryConfig.ChartJs
    $chartJsContent = Get-JSLibrary -Url $lib.Url -Name $lib.Name -Critical $lib.Critical

    $lib = $Script:LibraryConfig.PdfMake
    $pdfmakeContent = Get-JSLibrary -Url $lib.Url -Name $lib.Name -Critical $lib.Critical

    $lib = $Script:LibraryConfig.VfsFonts
    $vfsfontsContent = Get-JSLibrary -Url $lib.Url -Name $lib.Name -Critical $lib.Critical

    $lib = $Script:LibraryConfig.Html2Pdf
    $html2pdfContent = Get-JSLibrary -Url $lib.Url -Name $lib.Name -Critical $lib.Critical

    $lib = $Script:LibraryConfig.Html2Canvas
    $html2canvasContent = Get-JSLibrary -Url $lib.Url -Name $lib.Name -Critical $lib.Critical

    $pakoContent = ""
    if ($CompressData) {
        $lib = $Script:LibraryConfig.Pako
        $pakoContent = Get-JSLibrary -Url $lib.Url -Name $lib.Name -Critical $false
    }

    # Step 4: Load templates
    Write-Output "Loading templates..."
    $htmlTemplatePath = Join-Path -Path $tempTemplates -ChildPath "dashboard.html"
    $cssTemplatePath = Join-Path -Path $tempTemplates -ChildPath "dashboard.css"
    $jsTemplatePath = Join-Path -Path $tempTemplates -ChildPath "dashboard.js"

    if (-not (Test-Path $htmlTemplatePath)) { throw "Template not found: dashboard.html" }
    if (-not (Test-Path $cssTemplatePath)) { throw "Template not found: dashboard.css" }
    if (-not (Test-Path $jsTemplatePath)) { throw "Template not found: dashboard.js" }

    $htmlTemplate = Get-Content -Path $htmlTemplatePath -Raw
    $cssContent = Get-Content -Path $cssTemplatePath -Raw
    $jsContent = Get-Content -Path $jsTemplatePath -Raw

    # Step 5: Normalize data
    Write-Output "Normalizing data..."
    $normalizedResult = ConvertTo-NormalizedData -Vulnerabilities $onboardedVulnerabilities -Machines $machines -AdvancedHuntingData $advancedHuntingData

    # Step 6: Convert to JSON
    Write-Output "Preparing data for embedding..."
    $lookupsJson = $normalizedResult.Lookups | ConvertTo-Json -Depth 10 -Compress
    $vulnsJson = $normalizedResult.Vulns | ConvertTo-Json -Depth 10 -Compress

    $lookupsSize = [math]::Round($lookupsJson.Length / 1KB, 1)
    $vulnsSize = [math]::Round($vulnsJson.Length / 1KB, 1)
    Write-Output "  Lookups: ${lookupsSize}KB, Vulns: ${vulnsSize}KB"

    # Step 7: Compress data if requested
    $dataIsCompressed = $false
    if ($CompressData) {
        Write-Output "  Compressing embedded data..."
        $combinedData = @{ lookups = $normalizedResult.Lookups; vulns = $normalizedResult.Vulns }
        $combinedJson = $combinedData | ConvertTo-Json -Depth 10 -Compress

        $bytes = [System.Text.Encoding]::UTF8.GetBytes($combinedJson)
        $memStream = [System.IO.MemoryStream]::new()
        $gzipStream = [System.IO.Compression.GZipStream]::new($memStream, [System.IO.Compression.CompressionMode]::Compress)
        $gzipStream.Write($bytes, 0, $bytes.Length)
        $gzipStream.Close()
        $compressedBytes = $memStream.ToArray()
        $memStream.Close()

        $compressedBase64 = [Convert]::ToBase64String($compressedBytes)
        $compressedSize = [math]::Round($compressedBase64.Length / 1KB, 1)
        Write-Output "  Compressed: ${compressedSize}KB"

        $lookupsJsonEscaped = ""
        $vulnsJsonEscaped = $compressedBase64
        $dataIsCompressed = $true
    }
    else {
        $lookupsJsonEscaped = $lookupsJson -replace '</script>', '<\/script>'
        $vulnsJsonEscaped = $vulnsJson -replace '</script>', '<\/script>'
    }

    # Step 8: Assemble final HTML
    Write-Output "Assembling dashboard HTML..."
    $dataFormatMarker = if ($dataIsCompressed) { "compressed" } else { "normalized" }
    $pakoScript = if ($CompressData -and $pakoContent) { "<script>$pakoContent</script>" } else { "" }

    # Use [string]::Replace() to avoid regex interpretation of $ in JS code
    $htmlOutput = $htmlTemplate
    $htmlOutput = $htmlOutput.Replace('__CSS_CONTENT__', $cssContent)
    $htmlOutput = $htmlOutput.Replace('__JS_CONTENT__', $jsContent)
    $htmlOutput = $htmlOutput.Replace('__LOOKUPS_DATA__', $lookupsJsonEscaped)
    $htmlOutput = $htmlOutput.Replace('__VULNS_DATA__', $vulnsJsonEscaped)
    $htmlOutput = $htmlOutput.Replace('__DATA_FORMAT__', $dataFormatMarker)
    $htmlOutput = $htmlOutput.Replace('__PAKO_CONTENT__', $pakoScript)
    $htmlOutput = $htmlOutput.Replace('__CHARTJS_CONTENT__', $chartJsContent)
    $htmlOutput = $htmlOutput.Replace('__PDFMAKE_CONTENT__', $pdfmakeContent)
    $htmlOutput = $htmlOutput.Replace('__VFSFONTS_CONTENT__', $vfsfontsContent)
    $htmlOutput = $htmlOutput.Replace('__HTML2PDF_CONTENT__', $html2pdfContent)
    $htmlOutput = $htmlOutput.Replace('__HTML2CANVAS_CONTENT__', $html2canvasContent)

    $dashboardOutputPath = Join-Path -Path $tempDashboards -ChildPath "VulnerabilityDashboard.html"
    $htmlOutput | Out-File -FilePath $dashboardOutputPath -Encoding UTF8

    $finalSize = [math]::Round((Get-Item $dashboardOutputPath).Length / 1MB, 2)
    Write-Output "  Dashboard generated: ${finalSize}MB"

    # -----------------------------------------------------------------
    # Stage E: Export results
    # -----------------------------------------------------------------
    Write-Output "`n--- Stage E: Export ($Export) ---"

    switch ($Export) {
        'BlobStorage' {
            Export-ToBlobStorage `
                -AccountName $StorageAccountName `
                -StorageToken $storageToken `
                -ExportsPath $tempExports `
                -DashboardPath $dashboardOutputPath `
                -UseGzip $useGzip
        }
        'SharePoint' {
            # Still upload to blob as primary, then also to SharePoint
            Export-ToBlobStorage `
                -AccountName $StorageAccountName `
                -StorageToken $storageToken `
                -ExportsPath $tempExports `
                -DashboardPath $dashboardOutputPath `
                -UseGzip $useGzip
            Export-ToSharePoint -DashboardPath $dashboardOutputPath
        }
        'StaticWebApp' {
            Export-ToBlobStorage `
                -AccountName $StorageAccountName `
                -StorageToken $storageToken `
                -ExportsPath $tempExports `
                -DashboardPath $dashboardOutputPath `
                -UseGzip $useGzip
            Export-ToStaticWebApp -DashboardPath $dashboardOutputPath
        }
    }

    # -----------------------------------------------------------------
    # Cleanup
    # -----------------------------------------------------------------
    Write-Output "`n--- Cleanup ---"
    if (Test-Path $tempRoot) {
        Remove-Item -Path $tempRoot -Recurse -Force
        Write-Output "  Temporary files cleaned up"
    }

    # -----------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------
    Write-Output "`n========================================"
    Write-Output "  Pipeline Complete!"
    Write-Output "========================================"
    Write-Output "  Vulnerabilities: $($onboardedVulnerabilities.Count)"
    Write-Output "  Devices: $($normalizedResult.Lookups.devices.Count)"
    Write-Output "  CVEs: $($normalizedResult.Lookups.cves.Count)"
    Write-Output "  Dashboard size: ${finalSize}MB"
    Write-Output "  Export target: $Export"
    Write-Output "  Completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') UTC"
}
catch {
    Write-Output "========================================"
    Write-Output "  Pipeline Failed!"
    Write-Output "========================================"
    Write-Output "Error: $_"
    Write-Output "Stack trace:"
    Write-Output $_.ScriptStackTrace

    # Cleanup on failure
    if ($tempRoot -and (Test-Path $tempRoot)) {
        Remove-Item -Path $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    throw
}
