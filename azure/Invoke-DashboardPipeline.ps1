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

$Script:MachineCurrentFileName = 'Machines_Current.json'
$Script:MachineHistoryFileName = 'Machines_History.json'
$Script:AdvancedHuntingCurrentFileName = 'AdvancedHunting_Current.json'

# =============================================================================
# HELPER FUNCTIONS - DIAGNOSTICS
# =============================================================================

function Write-MemoryUsage {
    <#
    .SYNOPSIS
        Writes current process memory usage to output for monitoring in Azure Automation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Label = ""
    )

    $proc = [System.Diagnostics.Process]::GetCurrentProcess()
    $workingSetMB = [math]::Round($proc.WorkingSet64 / 1MB, 1)
    $gcHeapMB     = [math]::Round([System.GC]::GetTotalMemory($false) / 1MB, 1)
    $prefix = if ($Label) { "[$Label] " } else { "" }
    Write-Output "  ${prefix}Memory — Working set: ${workingSetMB}MB  |  GC heap: ${gcHeapMB}MB"
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

function ConvertTo-CompactMachineRecord {
    <#
    .SYNOPSIS
        Projects a machine object down to the fields used by the dashboard.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$Machine
    )

    return [PSCustomObject]@{
        id                    = $Machine.PSObject.Properties['id']?.Value
        computerDnsName       = $Machine.PSObject.Properties['computerDnsName']?.Value
        rbacGroupName         = $Machine.PSObject.Properties['rbacGroupName']?.Value
        osPlatform            = $Machine.PSObject.Properties['osPlatform']?.Value
        osVersion             = $Machine.PSObject.Properties['osVersion']?.Value
        machineTags           = Get-NormalizedMachineTags -Tags $Machine.PSObject.Properties['machineTags']?.Value
        lastIpAddress         = $Machine.PSObject.Properties['lastIpAddress']?.Value
        lastExternalIpAddress = $Machine.PSObject.Properties['lastExternalIpAddress']?.Value
        healthStatus          = $Machine.PSObject.Properties['healthStatus']?.Value
        riskScore             = $Machine.PSObject.Properties['riskScore']?.Value
        exposureLevel         = $Machine.PSObject.Properties['exposureLevel']?.Value
        deviceValue           = $Machine.PSObject.Properties['deviceValue']?.Value
        managedBy             = $Machine.PSObject.Properties['managedBy']?.Value
        isAadJoined           = $Machine.PSObject.Properties['isAadJoined']?.Value
        lastSeen              = $Machine.PSObject.Properties['lastSeen']?.Value
        firstSeen             = $Machine.PSObject.Properties['firstSeen']?.Value
    }
}

function Get-NormalizedMachineTags {
    <#
    .SYNOPSIS
        Returns a stable, sorted tag array for machine records.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Tags
    )

    $tagList = [System.Collections.Generic.List[string]]::new()

    if ($null -eq $Tags) {
        return @()
    }

    if ($Tags -is [string]) {
        if (-not [string]::IsNullOrWhiteSpace($Tags)) {
            $tagList.Add($Tags)
        }
    }
    elseif ($Tags -is [System.Collections.IEnumerable]) {
        foreach ($tag in $Tags) {
            if (-not [string]::IsNullOrWhiteSpace([string]$tag)) {
                $tagList.Add([string]$tag)
            }
        }
    }
    else {
        $tagValue = [string]$Tags
        if (-not [string]::IsNullOrWhiteSpace($tagValue)) {
            $tagList.Add($tagValue)
        }
    }

    if ($tagList.Count -eq 0) {
        return @()
    }

    return @($tagList | Sort-Object -Unique)
}

function Get-MachineCurrentPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$BasePath
    )

    return Join-Path -Path $BasePath -ChildPath $Script:MachineCurrentFileName
}

function Get-MachineHistoryPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$BasePath
    )

    return Join-Path -Path $BasePath -ChildPath $Script:MachineHistoryFileName
}

function Get-AdvancedHuntingCurrentPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$BasePath
    )

    return Join-Path -Path $BasePath -ChildPath $Script:AdvancedHuntingCurrentFileName
}

function Test-IsLegacyMachineSnapshotFileName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    return ($Name -match '^Machines_\d{4}-\d{2}-\d{2}\.json$')
}

function Test-IsLegacyAdvancedHuntingSnapshotFileName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    return ($Name -match '^AdvancedHunting_\d+_\d{4}-\d{2}-\d{2}\.json$')
}

function Read-MachineRecordsFromFile {
    <#
    .SYNOPSIS
        Reads machine records from NDJSON or array JSON files.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $fileMode = Get-JsonFileMode -Path $Path
    if ($fileMode -eq 'Empty') {
        return
    }

    if ($fileMode -eq 'Array') {
        $rawContent = Get-Content -Path $Path -Raw
        $machineList = $rawContent | ConvertFrom-Json
        $rawContent = $null
        if ($null -eq $machineList) { return }
        if ($machineList -isnot [System.Array]) { $machineList = @($machineList) }

        foreach ($machine in $machineList) {
            if ($null -eq $machine) { continue }
            $record = ConvertTo-CompactMachineRecord -Machine $machine
            $stateHash = $machine.PSObject.Properties['stateHash']?.Value
            $observedOn = $machine.PSObject.Properties['observedOn']?.Value
            if ($stateHash) { Add-Member -InputObject $record -NotePropertyName stateHash -NotePropertyValue $stateHash }
            if ($observedOn) { Add-Member -InputObject $record -NotePropertyName observedOn -NotePropertyValue $observedOn }
            Write-Output $record
        }

        return
    }

    foreach ($line in [System.IO.File]::ReadLines($Path)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try {
            $machine = $line | ConvertFrom-Json
        }
        catch {
            Write-Warning "Parse error in $(Split-Path -Leaf $Path): $_"
            continue
        }

        if ($null -eq $machine) { continue }
        $record = ConvertTo-CompactMachineRecord -Machine $machine
        $stateHash = $machine.PSObject.Properties['stateHash']?.Value
        $observedOn = $machine.PSObject.Properties['observedOn']?.Value
        if ($stateHash) { Add-Member -InputObject $record -NotePropertyName stateHash -NotePropertyValue $stateHash }
        if ($observedOn) { Add-Member -InputObject $record -NotePropertyName observedOn -NotePropertyValue $observedOn }
        Write-Output $record
    }
}

function Get-AdvancedHuntingLastModifiedKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$LastModifiedTime,

        [Parameter(Mandatory = $false)]
        [string]$FallbackDate = ''
    )

    if ($null -ne $LastModifiedTime) {
        $rawValue = $LastModifiedTime.ToString().Trim()
        if (-not [string]::IsNullOrWhiteSpace($rawValue)) {
            try {
                return ([datetimeoffset]$rawValue).UtcDateTime.ToString('o')
            }
            catch {
                $normalized = Convert-ToYmdDate -DateValue $rawValue
                if ($normalized) {
                    return $normalized
                }

                return $rawValue
            }
        }
    }

    return $FallbackDate
}

function Read-AdvancedHuntingRecordsFromFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $fileMode = Get-JsonFileMode -Path $Path
    if ($fileMode -eq 'Empty') {
        return
    }

    if ($fileMode -eq 'Array') {
        $rawContent = Get-Content -Path $Path -Raw
        $records = $rawContent | ConvertFrom-Json
        $rawContent = $null
        if ($null -eq $records) { return }
        if ($records -isnot [System.Array]) { $records = @($records) }

        foreach ($record in $records) {
            if ($null -ne $record) {
                Write-Output $record
            }
        }

        return
    }

    foreach ($line in [System.IO.File]::ReadLines($Path)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try {
            $record = $line | ConvertFrom-Json
            if ($null -ne $record) {
                Write-Output $record
            }
        }
        catch {
            Write-Warning "Parse error in $(Split-Path -Leaf $Path): $_"
        }
    }
}

function Initialize-AdvancedHuntingStore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [switch]$RemoveLegacyFiles
    )

    $currentPath = Get-AdvancedHuntingCurrentPath -BasePath $Path
    $currentRecords = @{}
    $migratedLegacy = $false
    $legacyFiles = @(Get-ChildItem -Path $Path -Filter 'AdvancedHunting_*.json' -File | Where-Object { Test-IsLegacyAdvancedHuntingSnapshotFileName -Name $_.Name } | Sort-Object Name)

    if (Test-Path -Path $currentPath) {
        foreach ($record in Read-AdvancedHuntingRecordsFromFile -Path $currentPath) {
            $cveId = $record.PSObject.Properties['CveId']?.Value
            if ($cveId) {
                $currentRecords[$cveId] = $record
            }
        }
    }

    if ($legacyFiles.Count -gt 0) {
        foreach ($file in $legacyFiles) {
            $fallbackDate = [regex]::Match($file.Name, '\d{4}-\d{2}-\d{2}').Value
            foreach ($record in Read-AdvancedHuntingRecordsFromFile -Path $file.FullName) {
                $cveId = $record.PSObject.Properties['CveId']?.Value
                if (-not $cveId) { continue }

                $incomingKey = Get-AdvancedHuntingLastModifiedKey -LastModifiedTime $record.PSObject.Properties['LastModifiedTime']?.Value -FallbackDate $fallbackDate
                $existing = $currentRecords[$cveId]

                if ($null -eq $existing) {
                    $currentRecords[$cveId] = $record
                    $migratedLegacy = $true
                    continue
                }

                $existingKey = Get-AdvancedHuntingLastModifiedKey -LastModifiedTime $existing.PSObject.Properties['LastModifiedTime']?.Value -FallbackDate ''
                if ([string]::CompareOrdinal($incomingKey, $existingKey) -gt 0) {
                    $currentRecords[$cveId] = $record
                    $migratedLegacy = $true
                }
            }
        }

        if ($migratedLegacy) {
            Write-NdjsonRecordsFile -Path $currentPath -Records $currentRecords.Values
        }

        if ($RemoveLegacyFiles -and $currentRecords.Count -gt 0) {
            Remove-Item -Path $legacyFiles.FullName -Force -ErrorAction SilentlyContinue
        }
    }

    return @{
        CurrentPath    = $currentPath
        CurrentRecords = $currentRecords
        MigratedLegacy = $migratedLegacy
    }
}

function Get-MachineStateHash {
    <#
    .SYNOPSIS
        Computes a stable hash for machine state fields that matter historically.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$Machine
    )

    $state = [ordered]@{
        computerDnsName       = $Machine.PSObject.Properties['computerDnsName']?.Value
        rbacGroupName         = $Machine.PSObject.Properties['rbacGroupName']?.Value
        osPlatform            = $Machine.PSObject.Properties['osPlatform']?.Value
        osVersion             = $Machine.PSObject.Properties['osVersion']?.Value
        machineTags           = @(Get-NormalizedMachineTags -Tags $Machine.PSObject.Properties['machineTags']?.Value)
        lastIpAddress         = $Machine.PSObject.Properties['lastIpAddress']?.Value
        lastExternalIpAddress = $Machine.PSObject.Properties['lastExternalIpAddress']?.Value
        healthStatus          = $Machine.PSObject.Properties['healthStatus']?.Value
        riskScore             = $Machine.PSObject.Properties['riskScore']?.Value
        exposureLevel         = $Machine.PSObject.Properties['exposureLevel']?.Value
        deviceValue           = $Machine.PSObject.Properties['deviceValue']?.Value
        managedBy             = $Machine.PSObject.Properties['managedBy']?.Value
        isAadJoined           = $Machine.PSObject.Properties['isAadJoined']?.Value
    }

    $stateJson = $state | ConvertTo-Json -Compress -Depth 5
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($stateJson)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hashBytes = $sha256.ComputeHash($bytes)
    }
    finally {
        $sha256.Dispose()
    }

    return ([System.BitConverter]::ToString($hashBytes)).Replace('-', '').ToLowerInvariant()
}

function New-MachineSnapshotRecord {
    <#
    .SYNOPSIS
        Creates a machine snapshot record with observed date and state hash.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$Machine,

        [Parameter(Mandatory)]
        [string]$ObservedOn
    )

    $compactRecord = ConvertTo-CompactMachineRecord -Machine $Machine
    $snapshot = [ordered]@{}
    foreach ($property in $compactRecord.PSObject.Properties) {
        $snapshot[$property.Name] = $property.Value
    }
    $snapshot['observedOn'] = $ObservedOn
    $snapshot['stateHash'] = Get-MachineStateHash -Machine $compactRecord

    return [PSCustomObject]$snapshot
}

function Write-NdjsonRecordsFile {
    <#
    .SYNOPSIS
        Writes machine records as NDJSON.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [System.Collections.IEnumerable]$Records
    )

    $writer = [System.IO.StreamWriter]::new($Path, $false, [System.Text.UTF8Encoding]::new($false))
    try {
        foreach ($record in $Records) {
            if ($null -eq $record) { continue }
            $writer.WriteLine(($record | ConvertTo-Json -Compress -Depth 6))
        }
    }
    finally {
        $writer.Dispose()
    }
}

function Initialize-MachineHistoryStore {
    <#
    .SYNOPSIS
        Loads or migrates machine history/current files for export updates.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [switch]$RemoveLegacyFiles
    )

    $currentPath = Get-MachineCurrentPath -BasePath $Path
    $historyPath = Get-MachineHistoryPath -BasePath $Path
    $currentExists = Test-Path -Path $currentPath
    $historyExists = Test-Path -Path $historyPath
    $currentItem = if ($currentExists) { Get-Item -Path $currentPath } else { $null }
    $historyItem = if ($historyExists) { Get-Item -Path $historyPath } else { $null }
    $legacyFiles = @(Get-ChildItem -Path $Path -Filter 'Machines_*.json' -File | Where-Object { Test-IsLegacyMachineSnapshotFileName -Name $_.Name } | Sort-Object Name)
    $currentRecords = @{}
    $migratedLegacy = $false

    $loadHistory = $historyExists -and ((-not $currentExists) -or ($historyItem.LastWriteTimeUtc -gt $currentItem.LastWriteTimeUtc))

    if ($loadHistory) {
        foreach ($record in Read-MachineRecordsFromFile -Path $historyPath) {
            if (-not $record.id) { continue }
            if (-not $record.PSObject.Properties['stateHash']) {
                Add-Member -InputObject $record -NotePropertyName stateHash -NotePropertyValue (Get-MachineStateHash -Machine $record)
            }
            $currentRecords[$record.id] = $record
        }
    }
    elseif ($currentExists) {
        foreach ($record in Read-MachineRecordsFromFile -Path $currentPath) {
            if (-not $record.id) { continue }
            if (-not $record.PSObject.Properties['stateHash']) {
                Add-Member -InputObject $record -NotePropertyName stateHash -NotePropertyValue (Get-MachineStateHash -Machine $record)
            }
            if (-not $record.PSObject.Properties['observedOn']) {
                Add-Member -InputObject $record -NotePropertyName observedOn -NotePropertyValue (Get-Date -Format 'yyyy-MM-dd')
            }
            $currentRecords[$record.id] = $record
        }
    }

    if (($currentRecords.Count -eq 0) -and $legacyFiles.Count -gt 0) {
        $historyRecords = [System.Collections.Generic.List[object]]::new()

        foreach ($file in $legacyFiles) {
            $observedOn = [regex]::Match($file.Name, '\d{4}-\d{2}-\d{2}').Value
            foreach ($record in Read-MachineRecordsFromFile -Path $file.FullName) {
                if (-not $record.id) { continue }
                $snapshot = New-MachineSnapshotRecord -Machine $record -ObservedOn $observedOn
                $existing = $currentRecords[$snapshot.id]
                if (($null -eq $existing) -or ($existing.stateHash -ne $snapshot.stateHash)) {
                    $historyRecords.Add($snapshot)
                }
                $currentRecords[$snapshot.id] = $snapshot
            }
        }

        if ($historyRecords.Count -gt 0) {
            Write-NdjsonRecordsFile -Path $historyPath -Records $historyRecords
        }
        if ($currentRecords.Count -gt 0) {
            Write-NdjsonRecordsFile -Path $currentPath -Records $currentRecords.Values
        }
        if ($RemoveLegacyFiles) {
            Remove-Item -Path $legacyFiles.FullName -Force -ErrorAction SilentlyContinue
        }
        $migratedLegacy = $true
        $historyExists = Test-Path -Path $historyPath
        $currentExists = Test-Path -Path $currentPath
    }

    if ((-not $historyExists) -and $currentRecords.Count -gt 0) {
        $seedRecords = foreach ($record in $currentRecords.Values) {
            if (-not $record.PSObject.Properties['stateHash']) {
                Add-Member -InputObject $record -NotePropertyName stateHash -NotePropertyValue (Get-MachineStateHash -Machine $record)
            }
            if (-not $record.PSObject.Properties['observedOn']) {
                Add-Member -InputObject $record -NotePropertyName observedOn -NotePropertyValue (Get-Date -Format 'yyyy-MM-dd')
            }
            $record
        }
        Write-NdjsonRecordsFile -Path $historyPath -Records $seedRecords
    }

    if ((-not $currentExists) -and $currentRecords.Count -gt 0) {
        Write-NdjsonRecordsFile -Path $currentPath -Records $currentRecords.Values
    }

    if ($RemoveLegacyFiles -and $legacyFiles.Count -gt 0 -and $currentRecords.Count -gt 0) {
        Remove-Item -Path $legacyFiles.FullName -Force -ErrorAction SilentlyContinue
    }

    return @{
        CurrentPath    = $currentPath
        HistoryPath    = $historyPath
        CurrentRecords = $currentRecords
        MigratedLegacy = $migratedLegacy
    }
}

function Get-JsonFileMode {
    <#
    .SYNOPSIS
        Detects whether a JSON file starts as an array or line-delimited objects.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $reader = [System.IO.StreamReader]::new($Path, [System.Text.Encoding]::UTF8, $true)
    try {
        while (-not $reader.EndOfStream) {
            $charValue = $reader.Read()
            if ($charValue -lt 0) { break }
            $char = [char]$charValue
            if (-not [char]::IsWhiteSpace($char)) {
                if ($char -eq '[') { return 'Array' }
                return 'Ndjson'
            }
        }

        return 'Empty'
    }
    finally {
        $reader.Dispose()
    }
}

function Write-Base64FileContent {
    <#
    .SYNOPSIS
        Streams a file as base64 into an existing text writer.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.IO.TextWriter]$Writer,

        [Parameter(Mandatory)]
        [string]$FilePath
    )

    $stream = [System.IO.File]::OpenRead($FilePath)
    try {
        $buffer = New-Object byte[] 12288
        $carry = New-Object byte[] 2
        $carryCount = 0

        while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $total = $carryCount + $read
            $chunk = New-Object byte[] $total

            if ($carryCount -gt 0) {
                [System.Buffer]::BlockCopy($carry, 0, $chunk, 0, $carryCount)
            }

            [System.Buffer]::BlockCopy($buffer, 0, $chunk, $carryCount, $read)

            $alignedLength = $total - ($total % 3)
            if ($alignedLength -gt 0) {
                $Writer.Write([System.Convert]::ToBase64String($chunk, 0, $alignedLength))
            }

            $carryCount = $total - $alignedLength
            if ($carryCount -gt 0) {
                [System.Buffer]::BlockCopy($chunk, $alignedLength, $carry, 0, $carryCount)
            }
        }

        if ($carryCount -gt 0) {
            $Writer.Write([System.Convert]::ToBase64String($carry, 0, $carryCount))
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Write-CombinedPayloadGzip {
    <#
    .SYNOPSIS
        Streams the combined lookups and vulnerability payload into a gzip file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Lookups,

        [Parameter(Mandatory)]
        [string]$VulnsPath,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    $fileStream = $null
    $gzipStream = $null
    $writer = $null
    $vulnReader = $null

    try {
        $fileStream = [System.IO.File]::Create($OutputPath)
        $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Compress)
        $writer = [System.IO.StreamWriter]::new($gzipStream, [System.Text.UTF8Encoding]::new($false))

        $writer.Write('{"lookups":')
        $lookupsJson = $Lookups | ConvertTo-Json -Depth 10 -Compress
        $writer.Write($lookupsJson)
        $lookupsJson = $null

        $writer.Write(',"vulns":')
        $vulnReader = [System.IO.StreamReader]::new($VulnsPath, [System.Text.Encoding]::UTF8)
        $charBuffer = New-Object char[] 16384
        while (($charsRead = $vulnReader.Read($charBuffer, 0, $charBuffer.Length)) -gt 0) {
            $writer.Write($charBuffer, 0, $charsRead)
        }

        $writer.Write('}')
    }
    finally {
        if ($vulnReader) { $vulnReader.Dispose() }
        if ($writer) { $writer.Dispose() }
        elseif ($gzipStream) { $gzipStream.Dispose() }
        elseif ($fileStream) { $fileStream.Dispose() }
    }
}

function Write-TemplatedHtml {
    <#
    .SYNOPSIS
        Writes the final dashboard HTML without creating repeated full-document copies.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Template,

        [Parameter(Mandatory)]
        [array]$Segments,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    $writer = [System.IO.StreamWriter]::new($OutputPath, $false, [System.Text.UTF8Encoding]::new($false))
    try {
        $position = 0
        foreach ($segment in $Segments) {
            $placeholder = $segment.Placeholder
            $index = $Template.IndexOf($placeholder, $position, [System.StringComparison]::Ordinal)
            if ($index -lt 0) {
                throw "Template placeholder not found: $placeholder"
            }

            $writer.Write($Template.Substring($position, $index - $position))
            if ($segment.ContainsKey('Base64FilePath')) {
                Write-Base64FileContent -Writer $writer -FilePath $segment.Base64FilePath
            }
            else {
                $writer.Write([string]$segment.Value)
            }

            $position = $index + $placeholder.Length
        }

        $writer.Write($Template.Substring($position))
    }
    finally {
        $writer.Dispose()
    }
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

function Remove-Blob {
    <#
    .SYNOPSIS
        Deletes a blob from storage.
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
        Invoke-WebRequest -Uri $uri -Headers $headers -Method Delete -ErrorAction Stop | Out-Null
    }
    catch {
        if ($_.Exception.Response.StatusCode -ne 404) {
            throw "Failed to delete blob '$BlobName' from '$Container': $_"
        }
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
        Exports machine data from the MDE /api/machines endpoint into current/history files.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Headers,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    Write-Host "Exporting machine data from MDE API..."

    $uri = "$($Script:MdeApiUrl)/api/machines?`$filter=onboardingStatus eq 'Onboarded'"
    $pageCount = 0
    $observedOn = Get-Date -Format "yyyy-MM-dd"
    $store = Initialize-MachineHistoryStore -Path $OutputPath -RemoveLegacyFiles
    $historyWriter = $null

    try {
        $historyWriter = [System.IO.StreamWriter]::new($store.HistoryPath, $true, [System.Text.UTF8Encoding]::new($false))
        $machineCount = 0
        $changeCount = 0

        do {
            $pageCount++
            Write-Host "  Fetching page $pageCount..."
            $response = Invoke-RestMethod -Uri $uri -Headers $Headers -Method Get

            if ($response.value) {
                foreach ($machine in $response.value) {
                    $snapshot = New-MachineSnapshotRecord -Machine $machine -ObservedOn $observedOn
                    $existing = $store.CurrentRecords[$snapshot.id]
                    if (($null -eq $existing) -or ($existing.stateHash -ne $snapshot.stateHash)) {
                        $historyWriter.WriteLine(($snapshot | ConvertTo-Json -Depth 6 -Compress))
                        $changeCount++
                    }
                    $store.CurrentRecords[$snapshot.id] = $snapshot
                    $machineCount++
                }
            }

            $uri = if ($response.PSObject.Properties['@odata.nextLink']) {
                $response.'@odata.nextLink'
            } else { $null }
        } while ($uri)

        $historyWriter.Dispose()
        $historyWriter = $null
        Write-NdjsonRecordsFile -Path $store.CurrentPath -Records $store.CurrentRecords.Values
    }
    finally {
        if ($historyWriter) {
            $historyWriter.Dispose()
        }
    }

    Write-Host "  Total machines: $machineCount"
    Write-Host "  Machine state changes captured: $changeCount"
    if ($store.MigratedLegacy) {
        Write-Host "  Migrated legacy machine snapshots to current/history store"
    }
    Write-Host "  Saved: $(Split-Path -Leaf $store.CurrentPath), $(Split-Path -Leaf $store.HistoryPath)"
    return @($store.CurrentPath, $store.HistoryPath)
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
| summarize arg_max(LastModifiedTime, PublishedDate, VulnerabilityDescription, IsExploitAvailable, EpssScore, AffectedSoftware) by CveId
| project CveId, PublishedDate = format_datetime(PublishedDate, 'yyyy-MM-dd'), VulnerabilityDescription, IsExploitAvailable, EpssScore, AffectedSoftware, LastModifiedTime
"@

    $body = @{ Query = $query } | ConvertTo-Json

    $response = Invoke-RestMethod -Uri $Script:AdvancedHuntingUrl -Headers $Headers -Method Post -Body $body

    if (-not $response.Results -or $response.Results.Count -eq 0) {
        Write-Warning "Advanced Hunting query returned no results."
        return $null
    }

    $resultCount = $response.Results.Count
    Write-Host "  Retrieved $resultCount records"

    $store = Initialize-AdvancedHuntingStore -Path $OutputPath -RemoveLegacyFiles
    foreach ($result in $response.Results) {
        $cveId = $result.PSObject.Properties['CveId']?.Value
        if ($cveId) {
            $store.CurrentRecords[$cveId] = $result
        }
    }

    $outputFile = $store.CurrentPath
    Write-NdjsonRecordsFile -Path $outputFile -Records $store.CurrentRecords.Values
    $response = $null

    if ($store.MigratedLegacy) {
        Write-Host "  Migrated legacy Advanced Hunting snapshots to current cache"
    }
    Write-Host "  Saved: $(Split-Path -Leaf $outputFile)"
    return $outputFile
}

# =============================================================================
# HELPER FUNCTIONS - DATA PROCESSING (from Generate-VulnerabilityDashboard.ps1)
# =============================================================================

function Read-MachineData {
    <#
    .SYNOPSIS
        Reads the machine current-state store when available, otherwise falls back
        to the history file or legacy dated snapshots.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    Write-Host "Reading machine data from $Path..."
    $machines = @{}

    $currentPath = Get-MachineCurrentPath -BasePath $Path
    $historyPath = Get-MachineHistoryPath -BasePath $Path

    if (Test-Path -Path $currentPath) {
        Write-Host "  Using $(Split-Path -Leaf $currentPath)"
        foreach ($record in Read-MachineRecordsFromFile -Path $currentPath) {
            if ($record.id) {
                $machines[$record.id] = ConvertTo-CompactMachineRecord -Machine $record
            }
        }
    }
    elseif (Test-Path -Path $historyPath) {
        Write-Host "  Using $(Split-Path -Leaf $historyPath) to reconstruct current state"
        foreach ($record in Read-MachineRecordsFromFile -Path $historyPath) {
            if ($record.id) {
                $machines[$record.id] = ConvertTo-CompactMachineRecord -Machine $record
            }
        }
    }
    else {
        $machineFiles = @(Get-ChildItem -Path $Path -Filter "Machines_*.json" -File | Where-Object { Test-IsLegacyMachineSnapshotFileName -Name $_.Name } | Sort-Object Name -Descending)

        if ($machineFiles.Count -eq 0) {
            Write-Warning "No machine data files found."
            return @{}
        }

        Write-Host "  Found $($machineFiles.Count) legacy machine snapshot file(s)"
        foreach ($file in $machineFiles) {
            Write-Host "  Processing $($file.Name)..."
            foreach ($record in Read-MachineRecordsFromFile -Path $file.FullName) {
                if ($record.id -and -not $machines.ContainsKey($record.id)) {
                    $machines[$record.id] = ConvertTo-CompactMachineRecord -Machine $record
                }
            }
        }
    }

    Write-Host "  Loaded $($machines.Count) unique machines"
    return $machines
}

function Read-AdvancedHuntingData {
    <#
    .SYNOPSIS
        Reads the canonical AdvancedHunting_Current.json cache when present,
        otherwise falls back to legacy dated Advanced Hunting exports.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    Write-Host "Reading Advanced Hunting data from $Path..."

    $ahData = @{}
    $parseErrors = 0

    $currentPath = Get-AdvancedHuntingCurrentPath -BasePath $Path
    if (Test-Path -Path $currentPath) {
        Write-Host "  Using $(Split-Path -Leaf $currentPath)"
        $sourceFiles = @(Get-Item -Path $currentPath)
    }
    else {
        $sourceFiles = @(Get-ChildItem -Path $Path -Filter "AdvancedHunting_*.json" -File | Where-Object { Test-IsLegacyAdvancedHuntingSnapshotFileName -Name $_.Name } | Sort-Object Name -Descending)

        if ($sourceFiles.Count -eq 0) {
            Write-Host "  No Advanced Hunting files found. CVE enrichment skipped."
            return @{}
        }

        Write-Host "  Found $($sourceFiles.Count) legacy file(s)"
    }

    foreach ($file in $sourceFiles) {
        Write-Host "  Processing $($file.Name)..."
        foreach ($record in Read-AdvancedHuntingRecordsFromFile -Path $file.FullName) {
            try {
                $cveId = $record.CveId
                if ($cveId -and -not $ahData.ContainsKey($cveId)) {
                    $pdRaw = $record.PSObject.Properties['PublishedDate']?.Value
                    $ahData[$cveId] = @{
                        PublishedDate            = Convert-ToYmdDate -DateValue $pdRaw
                        VulnerabilityDescription = $record.PSObject.Properties['VulnerabilityDescription']?.Value
                        EpssScore                = $record.PSObject.Properties['EpssScore']?.Value
                        AffectedSoftware         = $record.PSObject.Properties['AffectedSoftware']?.Value
                    }
                }
            }
            catch {
                $parseErrors++
                if ($parseErrors -le 5) { Write-Warning "Failed to process Advanced Hunting record in $($file.Name): $_" }
            }
        }
    }

    Write-Host "  Loaded enrichment data for $($ahData.Count) unique CVEs"
    return $ahData
}

function Convert-CveUrl {
    <#
    .SYNOPSIS
        Converts old Microsoft CVE URLs to the new format.
    
    .DESCRIPTION
        Microsoft changed their CVE URL format from:
        https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-XXXX-XXXXX
        to:
        https://msrc.microsoft.com/update-guide/vulnerability/CVE-XXXX-XXXXX
        
        This function detects and converts old URLs to the new format.
    
    .PARAMETER Url
        The CVE URL to convert (if needed).
    
    .OUTPUTS
        The converted URL string, or null if input is null/empty.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Url
    )
    
    if ([string]::IsNullOrWhiteSpace($Url)) {
        return $Url
    }
    
    # Check if URL matches old format (with or without 'portal.' subdomain)
    if ($Url -match '^https://(?:portal\.)?msrc\.microsoft\.com/en-US/security-guidance/advisory/(CVE-\d{4}-\d+)') {
        $cveId = $Matches[1]
        return "https://msrc.microsoft.com/update-guide/vulnerability/$cveId"
    }
    
    return $Url
}

function Convert-ToYmdDate {
    <#
    .SYNOPSIS
        Normalizes date/datetime values to YYYY-MM-DD.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$DateValue
    )

    if ($null -eq $DateValue) {
        return $null
    }

    $raw = $DateValue.ToString().Trim()
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return $null
    }

    if ($raw -match '^\d{4}-\d{2}-\d{2}$') {
        return $raw
    }

    if ($raw -match '^(\d{1,2})/(\d{1,2})/(\d{4})') {
        $month = [int]$Matches[1]
        $day = [int]$Matches[2]
        $year = [int]$Matches[3]
        if ($month -ge 1 -and $month -le 12 -and $day -ge 1 -and $day -le 31) {
            return ('{0:D4}-{1:D2}-{2:D2}' -f $year, $month, $day)
        }
    }

    try {
        return ([datetime]$raw).ToString('yyyy-MM-dd')
    }
    catch {
        return $null
    }
}

# Keep the shared store helpers in this section aligned with the equivalent
# helpers in Invoke-VulnerabilityExport.ps1 and Generate-VulnerabilityDashboard.ps1.

function ConvertTo-NormalizedData {
    <#
    .SYNOPSIS
        Normalizes vulnerability data into compact lookup tables and indexed records.
    .DESCRIPTION
        Streams VulnExport_*.json files directly from DataPath — no intermediate List[PSObject].
        Applies the IsOnboarded filter inline, then transforms each record into:
        - Lookup tables for repeated strings (vendors, software, CVEs, etc.)
        - Compact vulnerability records using indices instead of strings
        - Machine data merged from separate source
        - Advanced Hunting enrichment (PublishedDate, VulnerabilityDescription, EpssScore)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DataPath,

        [Parameter(Mandatory)]
        [string]$VulnOutputPath,

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
        versions      = [System.Collections.Generic.List[string]]::new()
        dates         = [System.Collections.Generic.List[string]]::new()
        diskPaths     = [System.Collections.Generic.List[string]]::new()
        regPaths      = [System.Collections.Generic.List[string]]::new()
        affSoftware   = [System.Collections.Generic.List[string]]::new()
        batchTitles   = [System.Collections.Generic.List[string]]::new()
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
    $versionIndex = @{}
    $dateIndex = @{}
    $diskPathIndex = @{}
    $regPathIndex = @{}
    $affSoftwareIndex = @{}
    $batchTitleIndex = @{}

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

    $dateValueCache = @{}
    function Get-CachedYmdDate {
        param($dateValue)

        if ($null -eq $dateValue) {
            return $null
        }

        $cacheKey = $dateValue.ToString()
        if ($dateValueCache.ContainsKey($cacheKey)) {
            return $dateValueCache[$cacheKey]
        }

        $normalized = Convert-ToYmdDate -DateValue $dateValue
        $dateValueCache[$cacheKey] = $normalized
        return $normalized
    }

    $firstLastSwappedCount = 0
    $processedCount = 0
    $parseErrors = 0
    $hasNoTags = $false
    $vulnWriter = $null
    $isFirstVuln = $true

    $jsonFiles = Get-ChildItem -Path $DataPath -Filter "VulnExport_*.json" -File |
        Where-Object { $_.Name -notmatch '_enriched\.json$' }
    if ($jsonFiles.Count -eq 0) { throw "No VulnExport JSON files found in '$DataPath'." }
    Write-Host "  Found $($jsonFiles.Count) export file(s) to normalize..."

    try {
        $vulnWriter = [System.IO.StreamWriter]::new($VulnOutputPath, $false, [System.Text.UTF8Encoding]::new($false))
        $vulnWriter.Write('[')

        foreach ($file in $jsonFiles) {
            Write-Host "  Processing $($file.Name)..."
            foreach ($line in [System.IO.File]::ReadLines($file.FullName)) {
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                try { $v = $line | ConvertFrom-Json }
                catch {
                    $parseErrors++
                    if ($parseErrors -le 5) { Write-Warning "Parse error in $($file.Name): $_" }
                    continue
                }
                if ($v.PSObject.Properties['IsOnboarded']?.Value -ne $true) { continue }
                $processedCount++

                $deviceId = $v.DeviceId
                if (-not $deviceIndex.ContainsKey($deviceId)) {
                    $machine = $Machines[$deviceId]

                    $groupName = if ($machine) { $machine.PSObject.Properties['rbacGroupName']?.Value } else { $v.PSObject.Properties['RbacGroupName']?.Value }
                    if ([string]::IsNullOrWhiteSpace([string]$groupName)) {
                        $fallbackGroupName = $v.PSObject.Properties['RbacGroupName']?.Value
                        $groupName = if ([string]::IsNullOrWhiteSpace([string]$fallbackGroupName)) { '(none)' } else { $fallbackGroupName }
                    }
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
                    if ($tagIndices.Count -eq 0) { $hasNoTags = $true }

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
                            ls  = Get-CachedYmdDate -dateValue $machineLastSeen
                            fs  = Get-CachedYmdDate -dateValue $machineFirstSeen
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
                $cvssScore = $v.PSObject.Properties['CvssScore']?.Value
                $sevLevel = $v.PSObject.Properties['VulnerabilitySeverityLevel']?.Value
                $sevIdx = switch ($sevLevel) {
                    'Critical' { 0 }
                    'High' { 1 }
                    'Medium' { 2 }
                    'Low' { 3 }
                    default { -1 }
                }

                $exploitabilityLevel = $v.PSObject.Properties['ExploitabilityLevel']?.Value
                $expIdx = Get-OrCreateIndex -value $exploitabilityLevel -list $lookups.exploitLevels -indexMap $exploitIndex

                $cveBatchUrl = Convert-CveUrl -Url $v.PSObject.Properties['CveBatchUrl']?.Value
                $btValue = $v.PSObject.Properties['CveBatchTitle']?.Value
                $cveKey = (@(
                    [string]$cveId,
                    [string]$cvssScore,
                    [string]$sevLevel,
                    [string]$exploitabilityLevel,
                    [string]$cveBatchUrl,
                    [string]$btValue
                ) -join '|')

                if (-not $cveIndex.ContainsKey($cveKey)) {
                    $ahData = $AdvancedHuntingData[$cveId]
                    $publishedDate = $null
                    $vulnDescription = $null
                    $epssScore = $null
                    $affSoftwareIndices = $null
                    if ($ahData) {
                        $publishedDate = $ahData.PublishedDate
                        $vulnDescription = $ahData.VulnerabilityDescription
                        $epssScore = $ahData.EpssScore
                        if ($ahData.AffectedSoftware -and $ahData.AffectedSoftware.Count -gt 0) {
                            $affSoftwareIndices = [System.Collections.Generic.List[int]]::new()
                            foreach ($sw in $ahData.AffectedSoftware) {
                                $asIdx = Get-OrCreateIndex -value $sw -list $lookups.affSoftware -indexMap $affSoftwareIndex
                                if ($asIdx -ge 0) { $affSoftwareIndices.Add($asIdx) }
                            }
                        }
                    }

                    $btIdx = Get-OrCreateIndex -value $btValue -list $lookups.batchTitles -indexMap $batchTitleIndex

                    $cveIndex[$cveKey] = $lookups.cves.Count
                    $lookups.cves.Add([PSCustomObject]@{
                        id   = $cveId
                        sc   = $cvssScore
                        sv   = $sevIdx
                        ex   = $expIdx
                        u    = $cveBatchUrl
                        bt   = $btIdx
                        pd   = $publishedDate
                        desc = $vulnDescription
                        ep   = $epssScore
                        as   = $affSoftwareIndices
                    })
                }
                $cveIdx = $cveIndex[$cveKey]

                $recUpdate = $v.PSObject.Properties['RecommendedSecurityUpdate']?.Value
                $recUpdateId = $v.PSObject.Properties['RecommendedSecurityUpdateId']?.Value
                $recUpdateUrl = $v.PSObject.Properties['RecommendedSecurityUpdateUrl']?.Value
                $updateName = if ($recUpdate -and $recUpdate -ne '--') { $recUpdate } else { $null }
                if ($null -eq $updateName -or $updateName -eq '') {
                    $updIdx = -1
                } else {
                    $updateKey = @(
                        [string]$updateName,
                        [string]$recUpdateId,
                        [string]$recUpdateUrl
                    ) -join '|'
                    if ($updateIndex.ContainsKey($updateKey)) {
                        $updIdx = $updateIndex[$updateKey]
                    } else {
                        $updIdx = $lookups.updates.Count
                        $updateIndex[$updateKey] = $updIdx
                        $lookups.updates.Add([PSCustomObject]@{
                            n   = $updateName
                            id  = $recUpdateId
                            url = $recUpdateUrl
                        })
                    }
                }

                $firstSeenTs = $v.PSObject.Properties['FirstSeenTimestamp']?.Value
                $lastSeenTs = $v.PSObject.Properties['LastSeenTimestamp']?.Value
                $firstSeen = Get-CachedYmdDate -dateValue $firstSeenTs
                $lastSeen = Get-CachedYmdDate -dateValue $lastSeenTs

                if ($firstSeen -and $lastSeen -and $firstSeen -gt $lastSeen) {
                    $temp = $firstSeen
                    $firstSeen = $lastSeen
                    $lastSeen = $temp
                    $firstLastSwappedCount++
                }

                if (-not $firstSeen) { $firstSeen = '' }
                if (-not $lastSeen) { $lastSeen = '' }

                $firstSeenIdx = Get-OrCreateIndex -value $firstSeen -list $lookups.dates -indexMap $dateIndex
                $lastSeenIdx = Get-OrCreateIndex -value $lastSeen -list $lookups.dates -indexMap $dateIndex

                $versionStr = $v.PSObject.Properties['SoftwareVersion']?.Value
                $versionIdx = Get-OrCreateIndex -value $versionStr -list $lookups.versions -indexMap $versionIndex

                $rawDiskPaths = $v.PSObject.Properties['DiskPaths']?.Value
                $rawRegPaths = $v.PSObject.Properties['RegistryPaths']?.Value
                $diskPathIndices = $null
                $regPathIndices = $null
                if ($rawDiskPaths -and $rawDiskPaths.Count -gt 0) {
                    $diskPathIndices = [System.Collections.Generic.List[int]]::new()
                    foreach ($dp in $rawDiskPaths) {
                        $dpIdx = Get-OrCreateIndex -value $dp -list $lookups.diskPaths -indexMap $diskPathIndex
                        if ($dpIdx -ge 0) { $diskPathIndices.Add($dpIdx) }
                    }
                }
                if ($rawRegPaths -and $rawRegPaths.Count -gt 0) {
                    $regPathIndices = [System.Collections.Generic.List[int]]::new()
                    foreach ($rp in $rawRegPaths) {
                        $rpIdx = Get-OrCreateIndex -value $rp -list $lookups.regPaths -indexMap $regPathIndex
                        if ($rpIdx -ge 0) { $regPathIndices.Add($rpIdx) }
                    }
                }

                $secUpdateAvail = $v.PSObject.Properties['SecurityUpdateAvailable']?.Value
                $compactRecord = @(
                    $devIdx,
                    $cveIdx,
                    $swIdx,
                    $versionIdx,
                    $firstSeenIdx,
                    $lastSeenIdx,
                    [int]($secUpdateAvail -eq $true),
                    $updIdx,
                    $diskPathIndices,
                    $regPathIndices
                )

                if (-not $isFirstVuln) {
                    $vulnWriter.Write(',')
                }
                $vulnWriter.Write(($compactRecord | ConvertTo-Json -Compress -Depth 5))
                $isFirstVuln = $false
            }
        }

        $vulnWriter.Write(']')
    }
    finally {
        if ($vulnWriter) {
            $vulnWriter.Dispose()
        }
    }

    if ($parseErrors -gt 0) { Write-Host "  Parse errors: $parseErrors" }
    if ($processedCount -eq 0) { throw "No onboarded vulnerabilities found after streaming all export files." }
    Write-Host "  Loaded $processedCount onboarded vulnerability records"

    # Handle "(No Tags)" label
    $noTagsLabel = "(No Tags)"
    if ($hasNoTags -and -not $tagIndex.ContainsKey($noTagsLabel)) {
        $tagIndex[$noTagsLabel] = $lookups.tags.Count
        $lookups.tags.Add($noTagsLabel)
    }
    $noTagsIdx = if ($tagIndex.ContainsKey($noTagsLabel)) { $tagIndex[$noTagsLabel] } else { -1 }

    Write-Host "  Normalized: $($lookups.devices.Count) devices, $($lookups.cves.Count) CVEs, $($lookups.software.Count) software"
    if ($firstLastSwappedCount -gt 0) {
        Write-Warning "  Corrected $firstLastSwappedCount record(s) with FirstSeenTimestamp > LastSeenTimestamp"
    }

    $datasetVendors = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($vendor in $lookups.vendors) {
        [void]$datasetVendors.Add($vendor)
    }

    foreach ($cve in $lookups.cves) {
        if ($null -ne $cve.as -and $cve.as.Count -gt 0) {
            $filteredIndices = [System.Collections.Generic.List[int]]::new()
            foreach ($asIdx in $cve.as) {
                $swStr = $lookups.affSoftware[$asIdx]
                $separatorIndex = $swStr.IndexOf(':')
                $swVendor = if ($separatorIndex -ge 0) { $swStr.Substring(0, $separatorIndex) } else { $swStr }
                if ($datasetVendors.Contains($swVendor)) {
                    $filteredIndices.Add($asIdx)
                }
            }
            $cve.as = if ($filteredIndices.Count -gt 0) { $filteredIndices } else { $null }
        }
    }

    return @{
        Lookups = [PSCustomObject]@{
            vendors       = $lookups.vendors
            severities    = $lookups.severities
            exploitLevels = $lookups.exploitLevels
            groups        = $lookups.groups
            platforms     = $lookups.platforms
            tags          = $lookups.tags
            updates       = $lookups.updates
            versions      = $lookups.versions
            dates         = $lookups.dates
            diskPaths     = $lookups.diskPaths
            regPaths      = $lookups.regPaths
            affSoftware   = $lookups.affSoftware
            batchTitles   = $lookups.batchTitles
            devices       = $lookups.devices
            software      = $lookups.software
            cves          = $lookups.cves
            noTagsIdx     = $noTagsIdx
        }
        Quality = [PSCustomObject]@{
            FirstLastSwappedCount = $firstLastSwappedCount
        }
        VulnCount = $processedCount
        VulnsPath = $VulnOutputPath
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

        [string[]]$LegacyMachineBlobNames = @(),

        [string[]]$LegacyAdvancedHuntingBlobNames = @(),

        [bool]$UseGzip = $true
    )

    Write-Output "`nUploading results to blob storage..."

    # Upload new export files (compressed)
    $exportFiles = Get-ChildItem -Path $ExportsPath -Filter "*.json" -File
    foreach ($file in $exportFiles) {
        $isCanonicalStoreFile = $file.Name -in @($Script:MachineCurrentFileName, $Script:MachineHistoryFileName, $Script:AdvancedHuntingCurrentFileName)
        if ($UseGzip) {
            $gzPath = "$($file.FullName).gz"
            $blobName = "$($file.Name).gz"

            # Skip if this blob already exists
            if ((-not $isCanonicalStoreFile) -and (Test-BlobExists -AccountName $AccountName -Container $Script:BlobContainers.Exports -BlobName $blobName -StorageToken $StorageToken)) {
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
            if ((-not $isCanonicalStoreFile) -and (Test-BlobExists -AccountName $AccountName -Container $Script:BlobContainers.Exports -BlobName $blobName -StorageToken $StorageToken)) {
                Write-Output "  Skipping $blobName (already exists)"
                continue
            }
            Write-Output "  Uploading $($file.Name)..."
            Set-BlobContent -AccountName $AccountName -Container $Script:BlobContainers.Exports -BlobName $blobName -SourcePath $file.FullName -StorageToken $StorageToken -ContentType 'application/json' -AccessTier $Script:BlobAccessTiers.Exports
        }
    }

    foreach ($legacyBlob in $LegacyMachineBlobNames) {
        Write-Output "  Removing legacy machine snapshot blob $legacyBlob..."
        Remove-Blob -AccountName $AccountName -Container $Script:BlobContainers.Exports -BlobName $legacyBlob -StorageToken $StorageToken
    }

    foreach ($legacyBlob in $LegacyAdvancedHuntingBlobNames) {
        Write-Output "  Removing legacy Advanced Hunting snapshot blob $legacyBlob..."
        Remove-Blob -AccountName $AccountName -Container $Script:BlobContainers.Exports -BlobName $legacyBlob -StorageToken $StorageToken
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
    Write-MemoryUsage -Label "Start"

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

    Write-MemoryUsage -Label "Post-Auth"

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
    $legacyMachineBlobs = @($existingBlobs | Where-Object { $_ -match '^Machines_\d{4}-\d{2}-\d{2}\.json(\.gz)?$' })
    $legacyAdvancedHuntingBlobs = @($existingBlobs | Where-Object { $_ -match '^AdvancedHunting_\d+_\d{4}-\d{2}-\d{2}\.json(\.gz)?$' })
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

    Write-MemoryUsage -Label "Post-BlobDownload"

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

    Write-MemoryUsage -Label "Post-MdeExport"

    # -----------------------------------------------------------------
    # Stage D: Generate dashboard
    # -----------------------------------------------------------------
    Write-Output "`n--- Stage D: Generate dashboard ---"

    # Step 1: Read machine and Advanced Hunting data
    $machines = Read-MachineData -Path $tempExports
    $advancedHuntingData = Read-AdvancedHuntingData -Path $tempExports

    # Step 2 (skipped): vulnerability files are streamed directly inside ConvertTo-NormalizedData

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

    # Download pako for data decompression
    $lib = $Script:LibraryConfig.Pako
    $pakoContent = Get-JSLibrary -Url $lib.Url -Name $lib.Name -Critical $false
    Write-MemoryUsage -Label "JS Libraries"

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
    $tempVulnsPath = Join-Path -Path $tempRoot -ChildPath 'vulns.json'
    $tempPayloadPath = Join-Path -Path $tempRoot -ChildPath 'payload.json.gz'
    $normalizedResult = ConvertTo-NormalizedData -DataPath $tempExports -VulnOutputPath $tempVulnsPath -Machines $machines -AdvancedHuntingData $advancedHuntingData
    $machines = $null
    $advancedHuntingData = $null
    [GC]::Collect()

    # Step 6: Prepare payload for embedding
    Write-Output "Preparing data for embedding..."
    $vulnCount = $normalizedResult.VulnCount
    $deviceCount = $normalizedResult.Lookups.devices.Count
    $cveCount = $normalizedResult.Lookups.cves.Count
    $vulnsFileSize = [math]::Round((Get-Item $normalizedResult.VulnsPath).Length / 1KB, 1)
    Write-Output "  Vulns JSON file: ${vulnsFileSize}KB"

    Write-Output "  Compressing embedded data..."
    Write-CombinedPayloadGzip -Lookups $normalizedResult.Lookups -VulnsPath $normalizedResult.VulnsPath -OutputPath $tempPayloadPath
    $normalizedResult = $null
    [GC]::Collect()
    Write-MemoryUsage -Label "Post-Normalize"

    $compressedSize = [math]::Round((Get-Item $tempPayloadPath).Length / 1KB, 1)
    Write-Output "  Compressed: ${compressedSize}KB"

    $lookupsJsonEscaped = ""
    $dataQualitySectionHtml = ""
    $dataQualityMetaScript = ""
    Write-MemoryUsage -Label "Post-Compress"

    # Step 8: Assemble final HTML
    Write-Output "Assembling dashboard HTML..."
    $dataFormatMarker = "compressed"
    $pakoScript = if ($pakoContent) { "<script>$pakoContent</script>" } else { "" }

    $segments = @(
        @{ Placeholder = '__CSS_CONTENT__'; Value = $cssContent },
        @{ Placeholder = '__DATA_QUALITY_SECTION__'; Value = $dataQualitySectionHtml },
        @{ Placeholder = '__PAKO_CONTENT__'; Value = $pakoScript },
        @{ Placeholder = '__DATA_FORMAT__'; Value = $dataFormatMarker },
        @{ Placeholder = '__DATA_QUALITY_META_SCRIPT__'; Value = $dataQualityMetaScript },
        @{ Placeholder = '__LOOKUPS_DATA__'; Value = $lookupsJsonEscaped },
        @{ Placeholder = '__VULNS_DATA__'; Base64FilePath = $tempPayloadPath },
        @{ Placeholder = '__CHARTJS_CONTENT__'; Value = $chartJsContent },
        @{ Placeholder = '__PDFMAKE_CONTENT__'; Value = $pdfmakeContent },
        @{ Placeholder = '__VFSFONTS_CONTENT__'; Value = $vfsfontsContent },
        @{ Placeholder = '__HTML2PDF_CONTENT__'; Value = $html2pdfContent },
        @{ Placeholder = '__HTML2CANVAS_CONTENT__'; Value = $html2canvasContent },
        @{ Placeholder = '__JS_CONTENT__'; Value = $jsContent }
    )
    $cssContent = $null
    $jsContent = $null
    $lookupsJsonEscaped = $null
    $pakoScript = $null
    $chartJsContent = $null
    $pdfmakeContent = $null
    $vfsfontsContent = $null
    $html2pdfContent = $null
    $html2canvasContent = $null

    $dashboardOutputPath = Join-Path -Path $tempDashboards -ChildPath "VulnerabilityDashboard.html"
    Write-TemplatedHtml -Template $htmlTemplate -Segments $segments -OutputPath $dashboardOutputPath
    $htmlTemplate = $null
    $segments = $null
    [GC]::Collect()

    $finalSize = [math]::Round((Get-Item $dashboardOutputPath).Length / 1MB, 2)
    Write-Output "  Dashboard generated: ${finalSize}MB"
    Write-MemoryUsage -Label "Post-Assembly"

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
                -LegacyMachineBlobNames $legacyMachineBlobs `
                -LegacyAdvancedHuntingBlobNames $legacyAdvancedHuntingBlobs `
                -UseGzip $useGzip
        }
        'SharePoint' {
            # Still upload to blob as primary, then also to SharePoint
            Export-ToBlobStorage `
                -AccountName $StorageAccountName `
                -StorageToken $storageToken `
                -ExportsPath $tempExports `
                -DashboardPath $dashboardOutputPath `
                -LegacyMachineBlobNames $legacyMachineBlobs `
                -LegacyAdvancedHuntingBlobNames $legacyAdvancedHuntingBlobs `
                -UseGzip $useGzip
            Export-ToSharePoint -DashboardPath $dashboardOutputPath
        }
        'StaticWebApp' {
            Export-ToBlobStorage `
                -AccountName $StorageAccountName `
                -StorageToken $storageToken `
                -ExportsPath $tempExports `
                -DashboardPath $dashboardOutputPath `
                -LegacyMachineBlobNames $legacyMachineBlobs `
                -LegacyAdvancedHuntingBlobNames $legacyAdvancedHuntingBlobs `
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
    Write-Output "  Vulnerabilities: $vulnCount"
    Write-Output "  Devices: $deviceCount"
    Write-Output "  CVEs: $cveCount"
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
