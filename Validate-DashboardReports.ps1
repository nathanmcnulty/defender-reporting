[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$HtmlPath = (Join-Path $PSScriptRoot 'VulnerabilityDashboard.html'),

    [Parameter(Mandatory = $false)]
    [string]$ExportsPath = (Join-Path $PSScriptRoot 'exports'),

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Join-Path $PSScriptRoot 'sample-reports\dashboard-audit.json')
)

$ErrorActionPreference = 'Stop'

function Convert-ToYmdDate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$DateValue
    )

    if ($null -eq $DateValue) { return $null }

    $raw = $DateValue.ToString().Trim()
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }

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

function Convert-CveUrl {
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

    if ($Url -match '^https://(?:portal\.)?msrc\.microsoft\.com/en-US/security-guidance/advisory/(CVE-\d{4}-\d+)') {
        return "https://msrc.microsoft.com/update-guide/vulnerability/$($Matches[1])"
    }

    return $Url
}

function Get-StringArray {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) { return @() }
    if ($Value -is [string]) {
        if ([string]::IsNullOrWhiteSpace($Value)) { return @() }
        return @($Value)
    }

    if ($Value -is [System.Collections.IEnumerable]) {
        $result = [System.Collections.Generic.List[string]]::new()
        foreach ($item in $Value) {
            if ($null -eq $item) { continue }
            $text = [string]$item
            if (-not [string]::IsNullOrWhiteSpace($text)) {
                $result.Add($text)
            }
        }
        return @($result)
    }

    return @([string]$Value)
}

function Get-JsonFileMode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    foreach ($line in [System.IO.File]::ReadLines($Path)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $trimmed = $line.TrimStart()
        if ($trimmed.StartsWith('[')) { return 'Array' }
        return 'Lines'
    }

    return 'Empty'
}

function Read-JsonRecordsFromFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $mode = Get-JsonFileMode -Path $Path
    if ($mode -eq 'Empty') { return }

    if ($mode -eq 'Array') {
        $records = Get-Content -Path $Path -Raw | ConvertFrom-Json -Depth 100
        if ($null -eq $records) { return }
        if ($records -isnot [System.Array]) { $records = @($records) }
        foreach ($record in $records) {
            if ($null -ne $record) { Write-Output $record }
        }
        return
    }

    foreach ($line in [System.IO.File]::ReadLines($Path)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $record = $line | ConvertFrom-Json -Depth 100
        if ($null -ne $record) { Write-Output $record }
    }
}

function Get-MachineCurrentPath {
    param([string]$BasePath)
    return (Join-Path $BasePath 'Machines_Current.json')
}

function Get-AdvancedHuntingCurrentPath {
    param([string]$BasePath)
    return (Join-Path $BasePath 'AdvancedHunting_Current.json')
}

function Get-NormalizedGroupName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$GroupName
    )

    if ([string]::IsNullOrWhiteSpace($GroupName)) { return '(none)' }
    return $GroupName
}

function Get-BuildRemediationString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Row
    )

    $kbId = $null
    if ($Row.RecommendedSecurityUpdateId) {
        $kbText = [string]$Row.RecommendedSecurityUpdateId
        $kbId = if ($kbText.StartsWith('KB')) { $kbText } else { "KB$kbText" }
    }

    if ($Row.CveBatchTitle) {
        return $(if ($kbId) { "$($Row.CveBatchTitle) ($kbId)" } else { [string]$Row.CveBatchTitle })
    }

    if ($Row.RecommendedSecurityUpdate -and $kbId) {
        return "$($Row.RecommendedSecurityUpdate) ($kbId)"
    }

    if ($Row.RecommendedSecurityUpdate) {
        return [string]$Row.RecommendedSecurityUpdate
    }

    if ($kbId) {
        return $kbId
    }

    return 'Not Specified'
}

function Format-ProductPart {
    [CmdletBinding()]
    param([AllowNull()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return 'Unknown' }
    return (($Text -split '_') | ForEach-Object {
        if ([string]::IsNullOrWhiteSpace($_)) { return $_ }
        $_.Substring(0, 1).ToUpperInvariant() + $_.Substring(1).ToLowerInvariant()
    }) -join ' '
}

function Get-CanonicalRowSignature {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Row
    )

    $payload = [ordered]@{
        DeviceId = [string]$Row.DeviceId
        DeviceName = [string]$Row.DeviceName
        RbacGroupName = [string]$Row.RbacGroupName
        OSPlatform = [string]$Row.OSPlatform
        OSVersion = [string]$Row.OSVersion
        MachineTags = @((Get-StringArray $Row.MachineTags | Sort-Object -Unique))
        MachineIp = if ($Row.MachineInfo) { [string]$Row.MachineInfo.ip } else { '' }
        CveId = [string]$Row.CveId
        CvssScore = $Row.CvssScore
        VulnerabilitySeverityLevel = [string]$Row.VulnerabilitySeverityLevel
        ExploitabilityLevel = [string]$Row.ExploitabilityLevel
        CveBatchUrl = [string]$Row.CveBatchUrl
        CveBatchTitle = [string]$Row.CveBatchTitle
        PublishedDate = [string]$Row.PublishedDate
        VulnerabilityDescription = [string]$Row.VulnerabilityDescription
        EpssScore = $Row.EpssScore
        AffectedSoftware = @((Get-StringArray $Row.AffectedSoftware | Sort-Object -Unique))
        SoftwareVendor = [string]$Row.SoftwareVendor
        SoftwareName = [string]$Row.SoftwareName
        SoftwareVersion = [string]$Row.SoftwareVersion
        RecommendationReference = [string]$Row.RecommendationReference
        FirstSeenTimestamp = [string]$Row.FirstSeenTimestamp
        LastSeenTimestamp = [string]$Row.LastSeenTimestamp
        SecurityUpdateAvailable = [bool]$Row.SecurityUpdateAvailable
        RecommendedSecurityUpdate = [string]$Row.RecommendedSecurityUpdate
        RecommendedSecurityUpdateId = [string]$Row.RecommendedSecurityUpdateId
        RecommendedSecurityUpdateUrl = [string]$Row.RecommendedSecurityUpdateUrl
        DiskPaths = @((Get-StringArray $Row.DiskPaths | Sort-Object -Unique))
        RegistryPaths = @((Get-StringArray $Row.RegistryPaths | Sort-Object -Unique))
    }

    return ($payload | ConvertTo-Json -Compress -Depth 20)
}

function Get-ObjectSha256 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $InputObject
    )

    $json = $InputObject | ConvertTo-Json -Compress -Depth 100
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $hashBytes = [System.Security.Cryptography.SHA256]::HashData($bytes)
    return ([System.BitConverter]::ToString($hashBytes)).Replace('-', '').ToLowerInvariant()
}

function New-MachineInfoObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Machine
    )

    if ($null -eq $Machine) { return $null }

    return [PSCustomObject]@{
        ip = $Machine.lastIpAddress
        eip = $Machine.lastExternalIpAddress
        hs = $Machine.healthStatus
        rs = $Machine.riskScore
        el = $Machine.exposureLevel
        dv = $Machine.deviceValue
        mb = $Machine.managedBy
        aad = $Machine.isAadJoined
        ls = Convert-ToYmdDate -DateValue $Machine.lastSeen
        fs = Convert-ToYmdDate -DateValue $Machine.firstSeen
    }
}

function Load-Machines {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    $machines = @{}
    $currentPath = Get-MachineCurrentPath -BasePath $Path
    foreach ($record in Read-JsonRecordsFromFile -Path $currentPath) {
        if (-not $record.id) { continue }
        $tags = Get-StringArray -Value $record.machineTags
        $machines[[string]$record.id] = [PSCustomObject]@{
            id = [string]$record.id
            computerDnsName = [string]$record.computerDnsName
            rbacGroupName = [string]$record.rbacGroupName
            osPlatform = [string]$record.osPlatform
            osVersion = [string]$record.osVersion
            machineTags = $tags
            lastIpAddress = [string]$record.lastIpAddress
            lastExternalIpAddress = [string]$record.lastExternalIpAddress
            healthStatus = [string]$record.healthStatus
            riskScore = [string]$record.riskScore
            exposureLevel = [string]$record.exposureLevel
            deviceValue = [string]$record.deviceValue
            managedBy = [string]$record.managedBy
            isAadJoined = [bool]$record.isAadJoined
            lastSeen = $record.lastSeen
            firstSeen = $record.firstSeen
        }
    }
    return $machines
}

function Load-AdvancedHunting {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    $data = @{}
    $currentPath = Get-AdvancedHuntingCurrentPath -BasePath $Path
    foreach ($record in Read-JsonRecordsFromFile -Path $currentPath) {
        if (-not $record.CveId) { continue }
        $data[[string]$record.CveId] = [PSCustomObject]@{
            PublishedDate = Convert-ToYmdDate -DateValue $record.PublishedDate
            VulnerabilityDescription = $record.VulnerabilityDescription
            EpssScore = $record.EpssScore
            AffectedSoftware = Get-StringArray -Value $record.AffectedSoftware
        }
    }
    return $data
}

function Load-SourceRows {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ExportsPath,
        [Parameter(Mandatory = $true)]$Machines,
        [Parameter(Mandatory = $true)]$AdvancedHunting
    )

    $rawRows = [System.Collections.Generic.List[object]]::new()
    $vendorSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $sourceFiles = Get-ChildItem -Path $ExportsPath -Filter 'VulnExport_*.json' -File | Where-Object { $_.Name -notmatch '_enriched\.json$' }

    foreach ($file in $sourceFiles) {
        foreach ($record in Read-JsonRecordsFromFile -Path $file.FullName) {
            if ($record.PSObject.Properties['IsOnboarded']?.Value -ne $true) { continue }
            $rawRows.Add([PSCustomObject]@{
                FileName = $file.Name
                Record = $record
            })
            $vendor = [string]$record.PSObject.Properties['SoftwareVendor']?.Value
            if (-not [string]::IsNullOrWhiteSpace($vendor)) {
                [void]$vendorSet.Add($vendor)
            }
        }
    }

    $rows = [System.Collections.Generic.List[object]]::new()
    $firstLastSwappedCount = 0
    $missingMachineCount = 0

    foreach ($entry in $rawRows) {
        $record = $entry.Record
        $deviceId = [string]$record.DeviceId
        $machine = if ($Machines.ContainsKey($deviceId)) { $Machines[$deviceId] } else { $null }
        if ($null -eq $machine) { $missingMachineCount++ }

        $groupName = if ($machine) { [string]$machine.rbacGroupName } else { [string]$record.PSObject.Properties['RbacGroupName']?.Value }
        if ([string]::IsNullOrWhiteSpace($groupName)) {
            $fallback = [string]$record.PSObject.Properties['RbacGroupName']?.Value
            $groupName = if ([string]::IsNullOrWhiteSpace($fallback)) { '(none)' } else { $fallback }
        }

        $machineTags = if ($machine -and $machine.machineTags.Count -gt 0) {
            $machine.machineTags
        }
        elseif ($record.PSObject.Properties['MachineTags']?.Value) {
            Get-StringArray -Value $record.PSObject.Properties['MachineTags']?.Value
        }
        else {
            @()
        }

        $firstSeen = Convert-ToYmdDate -DateValue $record.PSObject.Properties['FirstSeenTimestamp']?.Value
        $lastSeen = Convert-ToYmdDate -DateValue $record.PSObject.Properties['LastSeenTimestamp']?.Value
        if ($firstSeen -and $lastSeen -and $firstSeen -gt $lastSeen) {
            $temp = $firstSeen
            $firstSeen = $lastSeen
            $lastSeen = $temp
            $firstLastSwappedCount++
        }
        if (-not $firstSeen) { $firstSeen = '' }
        if (-not $lastSeen) { $lastSeen = '' }

        $ahRecord = $AdvancedHunting[[string]$record.CveId]
        $affectedSoftware = $null
        if ($ahRecord -and $ahRecord.AffectedSoftware.Count -gt 0) {
            $filtered = [System.Collections.Generic.List[string]]::new()
            foreach ($software in $ahRecord.AffectedSoftware) {
                $vendor = if ($software -match ':') { $software.Split(':', 2)[0] } else { $software }
                if ($vendorSet.Contains($vendor)) {
                    $filtered.Add([string]$software)
                }
            }
            if ($filtered.Count -gt 0) {
                $affectedSoftware = @($filtered)
            }
        }

        $recommendedUpdate = [string]$record.PSObject.Properties['RecommendedSecurityUpdate']?.Value
        if ([string]::IsNullOrWhiteSpace($recommendedUpdate) -or $recommendedUpdate -eq '--') {
            $recommendedUpdate = $null
        }

        $updateId = if ($recommendedUpdate) { [string]$record.PSObject.Properties['RecommendedSecurityUpdateId']?.Value } else { $null }
        $updateUrl = if ($recommendedUpdate) { [string]$record.PSObject.Properties['RecommendedSecurityUpdateUrl']?.Value } else { $null }

        $rows.Add([PSCustomObject]@{
            SourceFile = $entry.FileName
            SourceId = [string]$record.Id
            DeviceId = $deviceId
            DeviceName = if ($machine) { [string]$machine.computerDnsName } elseif ($record.PSObject.Properties['DeviceName']?.Value) { [string]$record.PSObject.Properties['DeviceName']?.Value } else { '(no machine data)' }
            RbacGroupName = $groupName
            OSPlatform = if ($machine) { [string]$machine.osPlatform } else { [string]$record.PSObject.Properties['OSPlatform']?.Value }
            OSVersion = if ($machine) { [string]$machine.osVersion } else { [string]$record.PSObject.Properties['OSVersion']?.Value }
            MachineTags = $machineTags
            MachineInfo = New-MachineInfoObject -Machine $machine
            CveId = [string]$record.CveId
            CvssScore = $record.PSObject.Properties['CvssScore']?.Value
            VulnerabilitySeverityLevel = [string]$record.PSObject.Properties['VulnerabilitySeverityLevel']?.Value
            ExploitabilityLevel = [string]$record.PSObject.Properties['ExploitabilityLevel']?.Value
            CveBatchUrl = Convert-CveUrl -Url ([string]$record.PSObject.Properties['CveBatchUrl']?.Value)
            CveBatchTitle = [string]$record.PSObject.Properties['CveBatchTitle']?.Value
            PublishedDate = if ($ahRecord) { [string]$ahRecord.PublishedDate } else { $null }
            VulnerabilityDescription = if ($ahRecord) { [string]$ahRecord.VulnerabilityDescription } else { $null }
            EpssScore = if ($ahRecord) { $ahRecord.EpssScore } else { $null }
            AffectedSoftware = $affectedSoftware
            SoftwareVendor = [string]$record.PSObject.Properties['SoftwareVendor']?.Value
            SoftwareName = [string]$record.PSObject.Properties['SoftwareName']?.Value
            SoftwareVersion = [string]$record.PSObject.Properties['SoftwareVersion']?.Value
            RecommendationReference = [string]$record.PSObject.Properties['RecommendationReference']?.Value
            FirstSeenTimestamp = $firstSeen
            LastSeenTimestamp = $lastSeen
            SecurityUpdateAvailable = ($record.PSObject.Properties['SecurityUpdateAvailable']?.Value -eq $true)
            RecommendedSecurityUpdate = $recommendedUpdate
            RecommendedSecurityUpdateId = $updateId
            RecommendedSecurityUpdateUrl = $updateUrl
            DiskPaths = Get-StringArray -Value $record.PSObject.Properties['DiskPaths']?.Value
            RegistryPaths = Get-StringArray -Value $record.PSObject.Properties['RegistryPaths']?.Value
        })
    }

    return [PSCustomObject]@{
        Rows = $rows
        FirstLastSwappedCount = $firstLastSwappedCount
        MissingMachineCount = $missingMachineCount
        VendorSet = @($vendorSet)
        RawRowCount = $rawRows.Count
    }
}

function Load-DashboardPayload {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    $content = Get-Content -Path $Path -Raw
    $startMarker = '<script id="vulnsData" type="application/json">'
    $endMarker = '</script>'
    $startIndex = $content.IndexOf($startMarker)
    if ($startIndex -lt 0) {
        throw "Unable to locate embedded vulnerability payload in '$Path'."
    }
    $payloadStart = $startIndex + $startMarker.Length
    $payloadEnd = $content.IndexOf($endMarker, $payloadStart)
    if ($payloadEnd -lt 0) {
        throw "Unable to locate payload terminator in '$Path'."
    }

    $base64 = $content.Substring($payloadStart, $payloadEnd - $payloadStart).Trim()
    $bytes = [Convert]::FromBase64String($base64)

    $stream = [System.IO.MemoryStream]::new($bytes)
    try {
        $gzip = [System.IO.Compression.GZipStream]::new($stream, [System.IO.Compression.CompressionMode]::Decompress)
        try {
            $reader = [System.IO.StreamReader]::new($gzip, [System.Text.Encoding]::UTF8)
            try {
                $json = $reader.ReadToEnd()
            }
            finally {
                $reader.Dispose()
            }
        }
        finally {
            $gzip.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }

    return ($json | ConvertFrom-Json -Depth 100)
}

function Load-DashboardRows {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Payload)

    $rows = [System.Collections.Generic.List[object]]::new()
    $lookups = $Payload.lookups
    for ($i = 0; $i -lt $Payload.vulns.Count; $i++) {
        $v = $Payload.vulns[$i]
        $device = $lookups.devices[$v[0]]
        $cve = $lookups.cves[$v[1]]
        $software = $lookups.software[$v[2]]

        $machineTags = @()
        $tagIndices = @($device.t | Where-Object { $null -ne $_ })
        if ($tagIndices.Count -gt 0) {
            foreach ($tagIndex in $tagIndices) {
                $machineTags += [string]$lookups.tags[$tagIndex]
            }
        }

        $diskPaths = @()
        $diskPathIndices = @($v[8] | Where-Object { $null -ne $_ })
        if ($diskPathIndices.Count -gt 0) {
            foreach ($pathIndex in $diskPathIndices) {
                $diskPaths += [string]$lookups.diskPaths[$pathIndex]
            }
        }

        $registryPaths = @()
        $registryPathIndices = @($v[9] | Where-Object { $null -ne $_ })
        if ($registryPathIndices.Count -gt 0) {
            foreach ($pathIndex in $registryPathIndices) {
                $registryPaths += [string]$lookups.regPaths[$pathIndex]
            }
        }

        $affectedSoftware = $null
        $affectedSoftwareIndices = @($cve.as | Where-Object { $null -ne $_ })
        if ($affectedSoftwareIndices.Count -gt 0) {
            $resolved = [System.Collections.Generic.List[string]]::new()
            foreach ($index in $affectedSoftwareIndices) {
                $resolved.Add([string]$lookups.affSoftware[$index])
            }
            if ($resolved.Count -gt 0) {
                $affectedSoftware = @($resolved)
            }
        }

        $updateObject = if ($v[7] -ge 0) { $lookups.updates[$v[7]] } else { $null }

        $rows.Add([PSCustomObject]@{
            DeviceId = [string]$device.id
            DeviceName = [string]$device.n
            RbacGroupName = if ($lookups.groups[$device.g] -and -not [string]::IsNullOrWhiteSpace([string]$lookups.groups[$device.g])) { [string]$lookups.groups[$device.g] } else { '(none)' }
            OSPlatform = [string]$lookups.platforms[$device.o]
            OSVersion = [string]$device.ov
            MachineTags = $machineTags
            MachineInfo = if ($device.m) { [PSCustomObject]$device.m } else { $null }
            CveId = [string]$cve.id
            CvssScore = $cve.sc
            VulnerabilitySeverityLevel = if ($null -ne $cve.sv -and [int]$cve.sv -ge 0) { [string]$lookups.severities[[int]$cve.sv] } else { $null }
            ExploitabilityLevel = if ($cve.ex -ge 0) { [string]$lookups.exploitLevels[$cve.ex] } else { $null }
            CveBatchUrl = [string]$cve.u
            CveBatchTitle = if ($cve.bt -ge 0) { [string]$lookups.batchTitles[$cve.bt] } else { $null }
            PublishedDate = Convert-ToYmdDate -DateValue $cve.pd
            VulnerabilityDescription = if ($null -ne $cve.desc) { [string]$cve.desc } else { $null }
            EpssScore = if ($null -ne $cve.ep) { $cve.ep } else { $null }
            AffectedSoftware = $affectedSoftware
            SoftwareVendor = [string]$lookups.vendors[$software.v]
            SoftwareName = [string]$software.n
            SoftwareVersion = if ($v[3] -ge 0) { [string]$lookups.versions[$v[3]] } else { $null }
            RecommendationReference = [string]$software.r
            FirstSeenTimestamp = if ($v[4] -ge 0) { (Convert-ToYmdDate -DateValue $lookups.dates[$v[4]]) ?? '' } else { '' }
            LastSeenTimestamp = if ($v[5] -ge 0) { (Convert-ToYmdDate -DateValue $lookups.dates[$v[5]]) ?? '' } else { '' }
            SecurityUpdateAvailable = ($v[6] -eq 1)
            RecommendedSecurityUpdate = if ($updateObject) { [string]($updateObject.n ?? $updateObject) } else { $null }
            RecommendedSecurityUpdateId = if ($updateObject -and $updateObject.id) { [string]$updateObject.id } else { $null }
            RecommendedSecurityUpdateUrl = if ($updateObject -and $updateObject.url) { [string]$updateObject.url } else { $null }
            DiskPaths = $diskPaths
            RegistryPaths = $registryPaths
            _index = $i
        })
    }

    return $rows
}

function Compare-RowSets {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$ExpectedRows,
        [Parameter(Mandatory = $true)]$ActualRows
    )

    $expectedMap = @{}
    foreach ($row in $ExpectedRows) {
        $signature = Get-CanonicalRowSignature -Row $row
        $expectedMap[$signature] = 1 + ($expectedMap[$signature] ?? 0)
    }

    $actualMap = @{}
    foreach ($row in $ActualRows) {
        $signature = Get-CanonicalRowSignature -Row $row
        $actualMap[$signature] = 1 + ($actualMap[$signature] ?? 0)
    }

    $missingSamples = [System.Collections.Generic.List[object]]::new()
    $extraSamples = [System.Collections.Generic.List[object]]::new()
    $missingCount = 0
    $extraCount = 0

    foreach ($key in $expectedMap.Keys) {
        $actualCount = $actualMap[$key] ?? 0
        if ($actualCount -lt $expectedMap[$key]) {
            $diff = $expectedMap[$key] - $actualCount
            $missingCount += $diff
            if ($missingSamples.Count -lt 5) {
                $missingSamples.Add([PSCustomObject]@{
                    MissingOccurrences = $diff
                    Signature = ($key | ConvertFrom-Json -Depth 20)
                })
            }
        }
    }

    foreach ($key in $actualMap.Keys) {
        $expectedCount = $expectedMap[$key] ?? 0
        if ($expectedCount -lt $actualMap[$key]) {
            $diff = $actualMap[$key] - $expectedCount
            $extraCount += $diff
            if ($extraSamples.Count -lt 5) {
                $extraSamples.Add([PSCustomObject]@{
                    ExtraOccurrences = $diff
                    Signature = ($key | ConvertFrom-Json -Depth 20)
                })
            }
        }
    }

    return [PSCustomObject]@{
        Match = ($missingCount -eq 0 -and $extraCount -eq 0)
        ExpectedRows = $ExpectedRows.Count
        ActualRows = $ActualRows.Count
        MissingCount = $missingCount
        ExtraCount = $extraCount
        MissingSamples = $missingSamples
        ExtraSamples = $extraSamples
    }
}

function Get-DateRange {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Rows)

    $firstDates = @($Rows | ForEach-Object { $_.FirstSeenTimestamp } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object)
    $lastDates = @($Rows | ForEach-Object { $_.LastSeenTimestamp } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object)
    return [PSCustomObject]@{
        Start = $firstDates[0]
        End = $lastDates[-1]
    }
}

function Get-DateSeries {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$StartDate,
        [Parameter(Mandatory = $true)][string]$EndDate
    )

    $dates = [System.Collections.Generic.List[string]]::new()
    $current = [datetime]$StartDate
    $end = [datetime]$EndDate
    while ($current -le $end) {
        $dates.Add($current.ToString('yyyy-MM-dd'))
        $current = $current.AddDays(1)
    }
    return $dates
}

function Get-StatsReport {
    param([Parameter(Mandatory = $true)]$Rows)

    $counts = [ordered]@{ Critical = 0; High = 0; Medium = 0; Low = 0 }
    foreach ($row in $Rows) {
        if ($row.VulnerabilitySeverityLevel -and $counts.Contains($row.VulnerabilitySeverityLevel)) {
            $counts[$row.VulnerabilitySeverityLevel]++
        }
    }
    return [PSCustomObject]$counts
}

function Get-ActiveChartReport {
    param([Parameter(Mandatory = $true)]$Rows)

    $range = Get-DateRange -Rows $Rows
    $dates = Get-DateSeries -StartDate $range.Start -EndDate $range.End
    $events = @{}

    foreach ($row in $Rows) {
        $startDate = $row.FirstSeenTimestamp
        $endDateExclusive = ([datetime]$row.LastSeenTimestamp).AddDays(1).ToString('yyyy-MM-dd')
        if ($endDateExclusive -le $startDate) {
            $endDateExclusive = ([datetime]$startDate).AddDays(1).ToString('yyyy-MM-dd')
        }

        if (-not $events.ContainsKey($startDate)) { $events[$startDate] = [PSCustomObject]@{ Starts = [System.Collections.Generic.List[object]]::new(); Ends = [System.Collections.Generic.List[object]]::new() } }
        if (-not $events.ContainsKey($endDateExclusive)) { $events[$endDateExclusive] = [PSCustomObject]@{ Starts = [System.Collections.Generic.List[object]]::new(); Ends = [System.Collections.Generic.List[object]]::new() } }
        $events[$startDate].Starts.Add($row)
        $events[$endDateExclusive].Ends.Add($row)
    }

    $severity = @{ Critical = 0; High = 0; Medium = 0; Low = 0 }
    $deviceActive = @{}
    $total = 0
    $series = [System.Collections.Generic.List[object]]::new()

    foreach ($date in $dates) {
        if ($events.ContainsKey($date)) {
            foreach ($row in $events[$date].Starts) {
                $total++
                if ($row.VulnerabilitySeverityLevel -and $severity.ContainsKey($row.VulnerabilitySeverityLevel)) { $severity[$row.VulnerabilitySeverityLevel]++ }
                $deviceActive[$row.DeviceName] = 1 + ($deviceActive[$row.DeviceName] ?? 0)
            }
            foreach ($row in $events[$date].Ends) {
                if ($total -gt 0) { $total-- }
                if ($row.VulnerabilitySeverityLevel -and $severity.ContainsKey($row.VulnerabilitySeverityLevel) -and $severity[$row.VulnerabilitySeverityLevel] -gt 0) { $severity[$row.VulnerabilitySeverityLevel]-- }
                $count = $deviceActive[$row.DeviceName] ?? 0
                if ($count -le 1) { $deviceActive.Remove($row.DeviceName) } else { $deviceActive[$row.DeviceName] = $count - 1 }
            }
        }

        $series.Add([PSCustomObject]@{
            Date = $date
            Critical = $severity.Critical
            High = $severity.High
            Medium = $severity.Medium
            Low = $severity.Low
            Total = $total
            Devices = $deviceActive.Count
        })
    }

    return $series
}

function Get-RemediationChartReport {
    param([Parameter(Mandatory = $true)]$Rows)

    $range = Get-DateRange -Rows $Rows
    $dates = Get-DateSeries -StartDate $range.Start -EndDate $range.End
    $index = @{}
    foreach ($row in $Rows) {
        $lastSeen = $row.LastSeenTimestamp
        if (-not $index.ContainsKey($lastSeen)) {
            $index[$lastSeen] = [System.Collections.Generic.List[object]]::new()
        }
        $index[$lastSeen].Add($row)
    }

    $series = [System.Collections.Generic.List[object]]::new()
    foreach ($date in $dates) {
        $items = if ($index.ContainsKey($date)) { $index[$date] } else { @() }
        $devices = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $severity = @{ Critical = 0; High = 0; Medium = 0; Low = 0 }
        foreach ($row in $items) {
            [void]$devices.Add([string]$row.DeviceName)
            if ($row.VulnerabilitySeverityLevel -and $severity.ContainsKey($row.VulnerabilitySeverityLevel)) { $severity[$row.VulnerabilitySeverityLevel]++ }
        }

        $series.Add([PSCustomObject]@{
            Date = $date
            Critical = $severity.Critical
            High = $severity.High
            Medium = $severity.Medium
            Low = $severity.Low
            Total = $items.Count
            Devices = $devices.Count
        })
    }

    return $series
}

function Get-RemediationTableReport {
    param([Parameter(Mandatory = $true)]$Rows)

    $map = @{}
    foreach ($row in $Rows) {
        $vendor = Format-ProductPart -Text $row.SoftwareVendor
        $software = Format-ProductPart -Text $row.SoftwareName
        $remediation = Get-BuildRemediationString -Row $row
        $key = "$vendor|$software|$remediation"
        if (-not $map.ContainsKey($key)) {
            $map[$key] = [PSCustomObject]@{
                Key = $key
                Vendor = $vendor
                Software = $software
                Remediation = $remediation
                Devices = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                Vulnerabilities = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                Exploits = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                Kits = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                RowCount = 0
            }
        }

        $item = $map[$key]
        [void]$item.Devices.Add([string]$row.DeviceId)
        [void]$item.Vulnerabilities.Add([string]$row.CveId)
        if ($row.ExploitabilityLevel -in @('ExploitIsVerified', 'ExploitIsPublic', 'ExploitIsInKit')) {
            [void]$item.Exploits.Add([string]$row.CveId)
        }
        if ($row.ExploitabilityLevel -eq 'ExploitIsInKit') {
            [void]$item.Kits.Add([string]$row.CveId)
        }
        $item.RowCount++
    }

    return @($map.Values | ForEach-Object {
        [PSCustomObject]@{
            Key = $_.Key
            Devices = $_.Devices.Count
            Vulnerabilities = $_.Vulnerabilities.Count
            Exploits = $_.Exploits.Count
            Kits = $_.Kits.Count
            RowCount = $_.RowCount
        }
    } | Sort-Object Key)
}

function Get-RemediationDetailsReport {
    param([Parameter(Mandatory = $true)]$Rows)

    $map = @{}
    foreach ($row in $Rows) {
        $remediation = Get-BuildRemediationString -Row $row
        $key = "$($row.LastSeenTimestamp)|$remediation"
        if (-not $map.ContainsKey($key)) {
            $map[$key] = [PSCustomObject]@{
                Key = $key
                Date = [string]$row.LastSeenTimestamp
                Remediation = $remediation
                Devices = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                Vulnerabilities = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            }
        }
        [void]$map[$key].Devices.Add([string]$row.DeviceName)
        [void]$map[$key].Vulnerabilities.Add([string]$row.CveId)
    }

    return @($map.Values | ForEach-Object {
        [PSCustomObject]@{
            Key = $_.Key
            Date = $_.Date
            Remediation = $_.Remediation
            Devices = $_.Devices.Count
            Vulnerabilities = $_.Vulnerabilities.Count
            Total = ($_.Devices.Count * $_.Vulnerabilities.Count)
        }
    } | Sort-Object Date, Remediation)
}

function Get-ImpactReport {
    param([Parameter(Mandatory = $true)]$Rows)

    $remediationMap = @{}
    foreach ($row in $Rows) {
        $remediation = Get-BuildRemediationString -Row $row
        if (-not $remediationMap.ContainsKey($remediation)) {
            $remediationMap[$remediation] = [PSCustomObject]@{
                Name = $remediation
                Devices = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                Vulnerabilities = [System.Collections.Generic.List[object]]::new()
            }
        }
        [void]$remediationMap[$remediation].Devices.Add([string]$row.DeviceName)
        $remediationMap[$remediation].Vulnerabilities.Add($row)
    }

    $top25 = @($remediationMap.Values | ForEach-Object {
        $cves = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($row in $_.Vulnerabilities) { [void]$cves.Add([string]$row.CveId) }
        [PSCustomObject]@{
            Name = $_.Name
            Devices = $_.Devices.Count
            Cves = $cves.Count
            Impact = ($_.Devices.Count * $cves.Count)
            Rows = @($_.Vulnerabilities)
        }
    } | Sort-Object Impact, Name -Descending | Select-Object -First 25)

    $top25KeySet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($item in $top25) {
        foreach ($row in $item.Rows) {
            [void]$top25KeySet.Add((Get-CanonicalRowSignature -Row $row))
        }
    }

    $range = Get-DateRange -Rows $Rows
    $dates = Get-DateSeries -StartDate $range.Start -EndDate $range.End
    $events = @{}
    foreach ($row in $Rows) {
        $startDate = $row.FirstSeenTimestamp
        $endDateExclusive = ([datetime]$row.LastSeenTimestamp).AddDays(1).ToString('yyyy-MM-dd')
        if ($endDateExclusive -le $startDate) {
            $endDateExclusive = ([datetime]$startDate).AddDays(1).ToString('yyyy-MM-dd')
        }
        $signature = Get-CanonicalRowSignature -Row $row
        $isTop25 = $top25KeySet.Contains($signature)
        if (-not $events.ContainsKey($startDate)) { $events[$startDate] = [PSCustomObject]@{ Starts = [System.Collections.Generic.List[object]]::new(); Ends = [System.Collections.Generic.List[object]]::new() } }
        if (-not $events.ContainsKey($endDateExclusive)) { $events[$endDateExclusive] = [PSCustomObject]@{ Starts = [System.Collections.Generic.List[object]]::new(); Ends = [System.Collections.Generic.List[object]]::new() } }
        $events[$startDate].Starts.Add([PSCustomObject]@{ Row = $row; IsTop25 = $isTop25 })
        $events[$endDateExclusive].Ends.Add([PSCustomObject]@{ Row = $row; IsTop25 = $isTop25 })
    }

    $currentSeverity = @{ Critical = 0; High = 0; Medium = 0; Low = 0 }
    $projectedSeverity = @{ Critical = 0; High = 0; Medium = 0; Low = 0 }
    $currentTotal = 0
    $projectedTotal = 0
    $series = [System.Collections.Generic.List[object]]::new()

    foreach ($date in $dates) {
        if ($events.ContainsKey($date)) {
            foreach ($event in $events[$date].Starts) {
                $currentTotal++
                if ($event.Row.VulnerabilitySeverityLevel -and $currentSeverity.ContainsKey($event.Row.VulnerabilitySeverityLevel)) { $currentSeverity[$event.Row.VulnerabilitySeverityLevel]++ }
                if (-not $event.IsTop25) {
                    $projectedTotal++
                    if ($event.Row.VulnerabilitySeverityLevel -and $projectedSeverity.ContainsKey($event.Row.VulnerabilitySeverityLevel)) { $projectedSeverity[$event.Row.VulnerabilitySeverityLevel]++ }
                }
            }
            foreach ($event in $events[$date].Ends) {
                if ($currentTotal -gt 0) { $currentTotal-- }
                if ($event.Row.VulnerabilitySeverityLevel -and $currentSeverity.ContainsKey($event.Row.VulnerabilitySeverityLevel) -and $currentSeverity[$event.Row.VulnerabilitySeverityLevel] -gt 0) { $currentSeverity[$event.Row.VulnerabilitySeverityLevel]-- }
                if (-not $event.IsTop25) {
                    if ($projectedTotal -gt 0) { $projectedTotal-- }
                    if ($event.Row.VulnerabilitySeverityLevel -and $projectedSeverity.ContainsKey($event.Row.VulnerabilitySeverityLevel) -and $projectedSeverity[$event.Row.VulnerabilitySeverityLevel] -gt 0) { $projectedSeverity[$event.Row.VulnerabilitySeverityLevel]-- }
                }
            }
        }

        $series.Add([PSCustomObject]@{
            Date = $date
            CurrentCritical = $currentSeverity.Critical
            CurrentHigh = $currentSeverity.High
            CurrentMedium = $currentSeverity.Medium
            CurrentLow = $currentSeverity.Low
            CurrentTotal = $currentTotal
            ProjectedCritical = $projectedSeverity.Critical
            ProjectedHigh = $projectedSeverity.High
            ProjectedMedium = $projectedSeverity.Medium
            ProjectedLow = $projectedSeverity.Low
            ProjectedTotal = $projectedTotal
        })
    }

    return [PSCustomObject]@{
        Top25 = @($top25 | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name
                Devices = $_.Devices
                Cves = $_.Cves
                Impact = $_.Impact
            }
        })
        Series = $series
    }
}

function Get-DevicesByRemediationReport {
    param([Parameter(Mandatory = $true)]$Rows)

    $map = @{}
    foreach ($row in $Rows) {
        $updateName = if ($row.RecommendedSecurityUpdate) { [string]$row.RecommendedSecurityUpdate } else { 'Unknown' }
        $updateId = [string]$row.RecommendedSecurityUpdateId
        $osPlatform = if ($row.OSPlatform) { [string]$row.OSPlatform } else { 'Unknown' }
        $key = "$updateName|$updateId|$osPlatform"
        if (-not $map.ContainsKey($key)) {
            $map[$key] = [PSCustomObject]@{
                Key = $key
                Devices = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                Cves = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                CveDetails = @{}
            }
        }
        [void]$map[$key].Devices.Add([string]$row.DeviceId)
        [void]$map[$key].Cves.Add([string]$row.CveId)
        if (-not $map[$key].CveDetails.ContainsKey($row.CveId)) {
            $map[$key].CveDetails[$row.CveId] = [string]$row.VulnerabilitySeverityLevel
        }
    }

    return @($map.Values | ForEach-Object {
        $sev = @{ Critical = 0; High = 0; Medium = 0; Low = 0 }
        foreach ($severity in $_.CveDetails.Values) {
            if ($sev.ContainsKey($severity)) { $sev[$severity]++ }
        }
        [PSCustomObject]@{
            Key = $_.Key
            Devices = $_.Devices.Count
            Cves = $_.Cves.Count
            Critical = $sev.Critical
            High = $sev.High
            Medium = $sev.Medium
            Low = $sev.Low
        }
    } | Sort-Object Key)
}

function Get-RemediationsByDeviceReport {
    param([Parameter(Mandatory = $true)]$Rows)

    $map = @{}
    foreach ($row in $Rows) {
        $deviceId = [string]$row.DeviceId
        if (-not $map.ContainsKey($deviceId)) {
            $map[$deviceId] = [PSCustomObject]@{
                DeviceId = $deviceId
                Cves = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                DeviceCveSeverity = @{}
                Remediations = @{}
            }
        }

        [void]$map[$deviceId].Cves.Add([string]$row.CveId)
        if (-not $map[$deviceId].DeviceCveSeverity.ContainsKey($row.CveId)) {
            $map[$deviceId].DeviceCveSeverity[$row.CveId] = [string]$row.VulnerabilitySeverityLevel
        }

        $batchTitle = if ($row.CveBatchTitle) { [string]$row.CveBatchTitle } elseif ($row.RecommendedSecurityUpdate) { [string]$row.RecommendedSecurityUpdate } else { 'Unknown' }
        $updateId = [string]$row.RecommendedSecurityUpdateId
        $osPlatform = if ($row.OSPlatform) { [string]$row.OSPlatform } else { 'Unknown' }
        $remKey = "$batchTitle|$updateId|$osPlatform"
        if (-not $map[$deviceId].Remediations.ContainsKey($remKey)) {
            $map[$deviceId].Remediations[$remKey] = @{}
        }
        if (-not $map[$deviceId].Remediations[$remKey].ContainsKey($row.CveId)) {
            $map[$deviceId].Remediations[$remKey][$row.CveId] = [string]$row.VulnerabilitySeverityLevel
        }
    }

    return @($map.Values | ForEach-Object {
        $deviceSev = @{ Critical = 0; High = 0; Medium = 0; Low = 0 }
        foreach ($severity in $_.DeviceCveSeverity.Values) {
            if ($deviceSev.ContainsKey($severity)) { $deviceSev[$severity]++ }
        }

        $remediations = @($_.Remediations.GetEnumerator() | ForEach-Object {
            $sev = @{ Critical = 0; High = 0; Medium = 0; Low = 0 }
            foreach ($severity in $_.Value.Values) {
                if ($sev.ContainsKey($severity)) { $sev[$severity]++ }
            }
            [PSCustomObject]@{
                Key = $_.Key
                Cves = $_.Value.Count
                Critical = $sev.Critical
                High = $sev.High
                Medium = $sev.Medium
                Low = $sev.Low
            }
        } | Sort-Object Key)

        [PSCustomObject]@{
            DeviceId = $_.DeviceId
            RemediationCount = $_.Remediations.Count
            CveCount = $_.Cves.Count
            Critical = $deviceSev.Critical
            High = $deviceSev.High
            Medium = $deviceSev.Medium
            Low = $deviceSev.Low
            Remediations = $remediations
        }
    } | Sort-Object DeviceId)
}

function Get-EnrichmentAudit {
    param(
        [Parameter(Mandatory = $true)]$SourceRows,
        [Parameter(Mandatory = $true)]$DashboardRows
    )

    $sourceMap = @{}
    foreach ($row in $SourceRows) {
        if (-not $sourceMap.ContainsKey($row.CveId)) {
            $sourceMap[$row.CveId] = $row
        }
    }

    $dashboardMap = @{}
    foreach ($row in $DashboardRows) {
        if (-not $dashboardMap.ContainsKey($row.CveId)) {
            $dashboardMap[$row.CveId] = $row
        }
    }

    $cvEs = @($dashboardMap.Keys | Sort-Object)
    $publishedMismatch = 0
    $descriptionMismatch = 0
    $epssMismatch = 0
    $affectedSoftwareMismatch = 0
    $samples = [System.Collections.Generic.List[object]]::new()

    foreach ($cveId in $cvEs) {
        $source = $sourceMap[$cveId]
        $dash = $dashboardMap[$cveId]
        if ($null -eq $source -or $null -eq $dash) { continue }

        $sourcePublished = [string]$source.PublishedDate
        $dashPublished = [string]$dash.PublishedDate
        $sourceDescription = [string]$source.VulnerabilityDescription
        $dashDescription = [string]$dash.VulnerabilityDescription
        $sourceEpss = if ($null -ne $source.EpssScore) { [string]$source.EpssScore } else { '' }
        $dashEpss = if ($null -ne $dash.EpssScore) { [string]$dash.EpssScore } else { '' }
        $sourceAffected = @((Get-StringArray $source.AffectedSoftware | Sort-Object -Unique))
        $dashAffected = @((Get-StringArray $dash.AffectedSoftware | Sort-Object -Unique))

        $mismatch = $false
        if ($sourcePublished -ne $dashPublished) { $publishedMismatch++; $mismatch = $true }
        if ($sourceDescription -ne $dashDescription) { $descriptionMismatch++; $mismatch = $true }
        if ($sourceEpss -ne $dashEpss) { $epssMismatch++; $mismatch = $true }
        if ((($sourceAffected -join "`n") -ne ($dashAffected -join "`n"))) { $affectedSoftwareMismatch++; $mismatch = $true }

        if ($mismatch -and $samples.Count -lt 5) {
            $samples.Add([PSCustomObject]@{
                CveId = $cveId
                SourcePublishedDate = $sourcePublished
                DashboardPublishedDate = $dashPublished
                SourceEpss = $sourceEpss
                DashboardEpss = $dashEpss
                SourceAffectedSoftware = $sourceAffected
                DashboardAffectedSoftware = $dashAffected
                DescriptionMatches = ($sourceDescription -eq $dashDescription)
            })
        }
    }

    return [PSCustomObject]@{
        DashboardCveCount = $cvEs.Count
        PublishedDateMismatchCount = $publishedMismatch
        DescriptionMismatchCount = $descriptionMismatch
        EpssMismatchCount = $epssMismatch
        AffectedSoftwareMismatchCount = $affectedSoftwareMismatch
        Samples = $samples
    }
}

function Compare-ReportOutput {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)]$Expected,
        [Parameter(Mandatory = $true)]$Actual
    )

    $expectedHash = Get-ObjectSha256 -InputObject $Expected
    $actualHash = Get-ObjectSha256 -InputObject $Actual
    return [PSCustomObject]@{
        Name = $Name
        Match = ($expectedHash -eq $actualHash)
        ExpectedHash = $expectedHash
        ActualHash = $actualHash
        ExpectedCount = if ($Expected -is [System.Collections.ICollection]) { $Expected.Count } else { $null }
        ActualCount = if ($Actual -is [System.Collections.ICollection]) { $Actual.Count } else { $null }
        SampleExpected = if ($Expected -is [System.Collections.ICollection]) { $Expected | Select-Object -First 3 } else { $Expected }
        SampleActual = if ($Actual -is [System.Collections.ICollection]) { $Actual | Select-Object -First 3 } else { $Actual }
    }
}

function Get-DuplicateIdentityAudit {
    param([Parameter(Mandatory = $true)]$SourceRows)

    $byId = @{}
    foreach ($row in $SourceRows) {
        $id = [string]$row.SourceId
        if (-not $byId.ContainsKey($id)) {
            $byId[$id] = [System.Collections.Generic.List[object]]::new()
        }
        $byId[$id].Add($row)
    }

    $duplicateIds = @($byId.GetEnumerator() | Where-Object { $_.Value.Count -gt 1 })
    $overlapCount = 0
    $sampleOverlap = $null

    foreach ($entry in $duplicateIds) {
        $items = @($entry.Value | Sort-Object FirstSeenTimestamp, LastSeenTimestamp)
        $hasOverlap = $false
        for ($i = 0; $i -lt $items.Count -and -not $hasOverlap; $i++) {
            for ($j = $i + 1; $j -lt $items.Count; $j++) {
                $aStart = [datetime]$items[$i].FirstSeenTimestamp
                $aEnd = [datetime]$items[$i].LastSeenTimestamp
                $bStart = [datetime]$items[$j].FirstSeenTimestamp
                $bEnd = [datetime]$items[$j].LastSeenTimestamp
                if ($aStart -le $bEnd -and $bStart -le $aEnd) {
                    $hasOverlap = $true
                    $overlapCount++
                    if (-not $sampleOverlap) {
                        $sampleOverlap = [PSCustomObject]@{
                            SourceId = $entry.Key
                            Occurrences = $items.Count
                            Rows = $items | Select-Object -First 5 SourceFile, DeviceId, CveId, SoftwareVendor, SoftwareName, SoftwareVersion, FirstSeenTimestamp, LastSeenTimestamp
                        }
                    }
                    break
                }
            }
        }
    }

    $latestDate = @($SourceRows | ForEach-Object LastSeenTimestamp | Sort-Object)[-1]
    $activeRowsOnLatest = @($SourceRows | Where-Object { $_.FirstSeenTimestamp -le $latestDate -and $_.LastSeenTimestamp -ge $latestDate })
    $activeIdsOnLatest = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($row in $activeRowsOnLatest) {
        [void]$activeIdsOnLatest.Add([string]$row.SourceId)
    }

    return [PSCustomObject]@{
        TotalRows = $SourceRows.Count
        UniqueSourceIds = $byId.Count
        DuplicateSourceIdCount = $duplicateIds.Count
        DuplicateRowExcess = ($SourceRows.Count - $byId.Count)
        OverlappingDuplicateSourceIdCount = $overlapCount
        LatestObservedLastSeen = $latestDate
        ActiveRowsOnLatestObservedDate = $activeRowsOnLatest.Count
        ActiveUniqueSourceIdsOnLatestObservedDate = $activeIdsOnLatest.Count
        PotentialLatestDateInflation = ($activeRowsOnLatest.Count - $activeIdsOnLatest.Count)
        SampleOverlap = $sampleOverlap
    }
}

$machines = Load-Machines -Path $ExportsPath
$advancedHunting = Load-AdvancedHunting -Path $ExportsPath
$sourceResult = Load-SourceRows -ExportsPath $ExportsPath -Machines $machines -AdvancedHunting $advancedHunting
$payload = Load-DashboardPayload -Path $HtmlPath
$dashboardRows = Load-DashboardRows -Payload $payload

$rowComparison = Compare-RowSets -ExpectedRows $sourceResult.Rows -ActualRows $dashboardRows
$enrichmentAudit = Get-EnrichmentAudit -SourceRows $sourceResult.Rows -DashboardRows $dashboardRows

$reportComparisons = @(
    Compare-ReportOutput -Name 'Stats' -Expected (Get-StatsReport -Rows $sourceResult.Rows) -Actual (Get-StatsReport -Rows $dashboardRows)
    Compare-ReportOutput -Name 'ActiveChart' -Expected (Get-ActiveChartReport -Rows $sourceResult.Rows) -Actual (Get-ActiveChartReport -Rows $dashboardRows)
    Compare-ReportOutput -Name 'RemediationTable' -Expected (Get-RemediationTableReport -Rows $sourceResult.Rows) -Actual (Get-RemediationTableReport -Rows $dashboardRows)
    Compare-ReportOutput -Name 'RemediationChart' -Expected (Get-RemediationChartReport -Rows $sourceResult.Rows) -Actual (Get-RemediationChartReport -Rows $dashboardRows)
    Compare-ReportOutput -Name 'RemediationDetails' -Expected (Get-RemediationDetailsReport -Rows $sourceResult.Rows) -Actual (Get-RemediationDetailsReport -Rows $dashboardRows)
    Compare-ReportOutput -Name 'Impact' -Expected (Get-ImpactReport -Rows $sourceResult.Rows) -Actual (Get-ImpactReport -Rows $dashboardRows)
    Compare-ReportOutput -Name 'DevicesByRemediation' -Expected (Get-DevicesByRemediationReport -Rows $sourceResult.Rows) -Actual (Get-DevicesByRemediationReport -Rows $dashboardRows)
    Compare-ReportOutput -Name 'RemediationsByDevice' -Expected (Get-RemediationsByDeviceReport -Rows $sourceResult.Rows) -Actual (Get-RemediationsByDeviceReport -Rows $dashboardRows)
)

$duplicateAudit = Get-DuplicateIdentityAudit -SourceRows $sourceResult.Rows

$qualityMeta = if ($payload.PSObject.Properties['quality'] -and $payload.quality) { $payload.quality } else { $null }

$result = [PSCustomObject]@{
    GeneratedOn = (Get-Date).ToString('o')
    HtmlPath = $HtmlPath
    ExportsPath = $ExportsPath
    Source = [PSCustomObject]@{
        RowCount = $sourceResult.Rows.Count
        MissingMachineCount = $sourceResult.MissingMachineCount
        FirstLastSwappedCount = $sourceResult.FirstLastSwappedCount
        UniqueVendors = @($sourceResult.VendorSet | Sort-Object)
    }
    Dashboard = [PSCustomObject]@{
        RowCount = $dashboardRows.Count
        Quality = $qualityMeta
    }
    RowComparison = $rowComparison
    EnrichmentAudit = $enrichmentAudit
    ReportComparisons = $reportComparisons
    DuplicateIdentityAudit = $duplicateAudit
}

$outputDirectory = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputDirectory) -and -not (Test-Path -Path $outputDirectory)) {
    [void](New-Item -Path $outputDirectory -ItemType Directory -Force)
}

$result | ConvertTo-Json -Depth 100 | Set-Content -Path $OutputPath -Encoding utf8
$result | ConvertTo-Json -Depth 20