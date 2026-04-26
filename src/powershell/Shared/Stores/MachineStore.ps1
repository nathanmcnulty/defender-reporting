
# Shared machine storage helpers used by export, generator, and the Azure runbook.

function ConvertTo-CompactMachineRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Machine
    )

    return [PSCustomObject]@{
        id                    = $Machine.PSObject.Properties['id']?.Value
        computerDnsName       = $Machine.PSObject.Properties['computerDnsName']?.Value
        rbacGroupName         = $Machine.PSObject.Properties['rbacGroupName']?.Value
        osPlatform            = $Machine.PSObject.Properties['osPlatform']?.Value
        osVersion             = $Machine.PSObject.Properties['osVersion']?.Value
        machineTags           = Get-NormalizedMachineTag -Tags $Machine.PSObject.Properties['machineTags']?.Value
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

function ConvertTo-NormalizationMachineTuple {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Machine
    )

    if ($null -eq $Machine) {
        return $null
    }

    if ($Machine -is [System.Array]) {
        $tuple = [object[]]$Machine
        if ($tuple.Length -ge 15) {
            return $tuple
        }

        if ($tuple.Length -ge 10) {
            $extendedTuple = [System.Collections.Generic.List[object]]::new()
            foreach ($value in $tuple) {
                $extendedTuple.Add($value) | Out-Null
            }

            while ($extendedTuple.Count -lt 15) {
                $extendedTuple.Add($null) | Out-Null
            }

            return $extendedTuple.ToArray()
        }
    }

    $ip = $Machine.PSObject.Properties['lastIpAddress']?.Value
    $externalIp = $Machine.PSObject.Properties['lastExternalIpAddress']?.Value
    $healthStatus = $Machine.PSObject.Properties['healthStatus']?.Value
    $riskScore = $Machine.PSObject.Properties['riskScore']?.Value
    $exposureLevel = $Machine.PSObject.Properties['exposureLevel']?.Value
    $deviceValue = $Machine.PSObject.Properties['deviceValue']?.Value
    $managedBy = $Machine.PSObject.Properties['managedBy']?.Value
    $isAadJoined = $Machine.PSObject.Properties['isAadJoined']?.Value
    $lastSeen = $Machine.PSObject.Properties['lastSeen']?.Value
    $firstSeen = $Machine.PSObject.Properties['firstSeen']?.Value
    $osVersion = $Machine.PSObject.Properties['osVersion']?.Value
    $computerDnsName = $Machine.PSObject.Properties['computerDnsName']?.Value
    $rbacGroupName = $Machine.PSObject.Properties['rbacGroupName']?.Value
    $osPlatform = $Machine.PSObject.Properties['osPlatform']?.Value
    $machineTags = @(Get-NormalizedMachineTag -Tags $Machine.PSObject.Properties['machineTags']?.Value)

    if (
        $null -eq $ip -and
        $null -eq $externalIp -and
        $null -eq $healthStatus -and
        $null -eq $riskScore -and
        $null -eq $exposureLevel -and
        $null -eq $deviceValue -and
        $null -eq $managedBy -and
        $null -eq $isAadJoined -and
        $null -eq $lastSeen -and
        $null -eq $firstSeen -and
        $null -eq $osVersion -and
        $null -eq $computerDnsName -and
        $null -eq $rbacGroupName -and
        $null -eq $osPlatform -and
        @($machineTags).Count -eq 0
    ) {
        return $null
    }

    return [object[]]@(
        $ip,
        $externalIp,
        $healthStatus,
        $riskScore,
        $exposureLevel,
        $deviceValue,
        $managedBy,
        $isAadJoined,
        $lastSeen,
        $firstSeen,
        $osVersion,
        $computerDnsName,
        $rbacGroupName,
        $osPlatform,
        @($machineTags)
    )
}

function Get-MachineJsonElementScalarValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Text.Json.JsonElement]$Element,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $property = [System.Text.Json.JsonElement]::new()
    if (-not $Element.TryGetProperty($Name, [ref]$property)) {
        return $null
    }

    switch ($property.ValueKind) {
        ([System.Text.Json.JsonValueKind]::Undefined) { return $null }
        ([System.Text.Json.JsonValueKind]::Null) { return $null }
        ([System.Text.Json.JsonValueKind]::String) { return $property.GetString() }
        ([System.Text.Json.JsonValueKind]::True) { return $true }
        ([System.Text.Json.JsonValueKind]::False) { return $false }
        ([System.Text.Json.JsonValueKind]::Number) {
            $int64Value = 0L
            if ($property.TryGetInt64([ref]$int64Value)) {
                return $int64Value
            }

            $doubleValue = 0.0
            if ($property.TryGetDouble([ref]$doubleValue)) {
                return $doubleValue
            }

            return $property.GetRawText()
        }
        default { return $property.GetRawText() }
    }
}

function Get-MachineJsonElementStringArrayValue {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Text.Json.JsonElement]$Element,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $property = [System.Text.Json.JsonElement]::new()
    if (-not $Element.TryGetProperty($Name, [ref]$property)) {
        return [string[]]@()
    }

    switch ($property.ValueKind) {
        ([System.Text.Json.JsonValueKind]::Undefined) { return [string[]]@() }
        ([System.Text.Json.JsonValueKind]::Null) { return [string[]]@() }
        ([System.Text.Json.JsonValueKind]::String) { return (Get-NormalizedMachineTag -Tags $property.GetString()) }
        ([System.Text.Json.JsonValueKind]::Array) {
            $tagList = [System.Collections.Generic.List[string]]::new()
            foreach ($item in $property.EnumerateArray()) {
                $tagValue = switch ($item.ValueKind) {
                    ([System.Text.Json.JsonValueKind]::String) { $item.GetString() }
                    ([System.Text.Json.JsonValueKind]::Null) { $null }
                    ([System.Text.Json.JsonValueKind]::Undefined) { $null }
                    default { $item.GetRawText() }
                }

                if (-not [string]::IsNullOrWhiteSpace([string]$tagValue)) {
                    $tagList.Add([string]$tagValue) | Out-Null
                }
            }

            return (Get-NormalizedMachineTag -Tags @($tagList))
        }
        default { return (Get-NormalizedMachineTag -Tags (Get-MachineJsonElementScalarValue -Element $Element -Name $Name)) }
    }
}

function ConvertFrom-MachineJsonElementToCompactMachineRecord {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Text.Json.JsonElement]$MachineElement
    )

    $machineId = [string](Get-MachineJsonElementScalarValue -Element $MachineElement -Name 'id')
    if ([string]::IsNullOrWhiteSpace($machineId)) {
        return $null
    }

    $observedOn = Get-MachineJsonElementScalarValue -Element $MachineElement -Name 'observedOn'
    $stateHash = Get-MachineJsonElementScalarValue -Element $MachineElement -Name 'stateHash'
    if ((Get-MachineJsonElementScalarValue -Element $MachineElement -Name 'removed') -eq $true) {
        return [PSCustomObject]@{
            id = $machineId
            observedOn = $observedOn
            removed = $true
            stateHash = $stateHash
        }
    }

    $record = [PSCustomObject]@{
        id                    = $machineId
        computerDnsName       = Get-MachineJsonElementScalarValue -Element $MachineElement -Name 'computerDnsName'
        rbacGroupName         = Get-MachineJsonElementScalarValue -Element $MachineElement -Name 'rbacGroupName'
        osPlatform            = Get-MachineJsonElementScalarValue -Element $MachineElement -Name 'osPlatform'
        osVersion             = Get-MachineJsonElementScalarValue -Element $MachineElement -Name 'osVersion'
        machineTags           = Get-MachineJsonElementStringArrayValue -Element $MachineElement -Name 'machineTags'
        lastIpAddress         = Get-MachineJsonElementScalarValue -Element $MachineElement -Name 'lastIpAddress'
        lastExternalIpAddress = Get-MachineJsonElementScalarValue -Element $MachineElement -Name 'lastExternalIpAddress'
        healthStatus          = Get-MachineJsonElementScalarValue -Element $MachineElement -Name 'healthStatus'
        riskScore             = Get-MachineJsonElementScalarValue -Element $MachineElement -Name 'riskScore'
        exposureLevel         = Get-MachineJsonElementScalarValue -Element $MachineElement -Name 'exposureLevel'
        deviceValue           = Get-MachineJsonElementScalarValue -Element $MachineElement -Name 'deviceValue'
        managedBy             = Get-MachineJsonElementScalarValue -Element $MachineElement -Name 'managedBy'
        isAadJoined           = Get-MachineJsonElementScalarValue -Element $MachineElement -Name 'isAadJoined'
        lastSeen              = Get-MachineJsonElementScalarValue -Element $MachineElement -Name 'lastSeen'
        firstSeen             = Get-MachineJsonElementScalarValue -Element $MachineElement -Name 'firstSeen'
    }

    if (-not [string]::IsNullOrWhiteSpace([string]$stateHash)) {
        Add-Member -InputObject $record -NotePropertyName stateHash -NotePropertyValue $stateHash
    }

    if (-not [string]::IsNullOrWhiteSpace([string]$observedOn)) {
        Add-Member -InputObject $record -NotePropertyName observedOn -NotePropertyValue $observedOn
    }

    return $record
}

function ConvertFrom-MachineJsonElementToNormalizationEntry {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Text.Json.JsonElement]$MachineElement
    )

    $machineId = [string](Get-MachineJsonElementScalarValue -Element $MachineElement -Name 'id')
    if ([string]::IsNullOrWhiteSpace($machineId)) {
        return $null
    }

    if ((Get-MachineJsonElementScalarValue -Element $MachineElement -Name 'removed') -eq $true) {
        return [PSCustomObject]@{
            id = $machineId
            removed = $true
        }
    }

    $tuple = [object[]]@(
        (Get-MachineJsonElementScalarValue -Element $MachineElement -Name 'lastIpAddress'),
        (Get-MachineJsonElementScalarValue -Element $MachineElement -Name 'lastExternalIpAddress'),
        (Get-MachineJsonElementScalarValue -Element $MachineElement -Name 'healthStatus'),
        (Get-MachineJsonElementScalarValue -Element $MachineElement -Name 'riskScore'),
        (Get-MachineJsonElementScalarValue -Element $MachineElement -Name 'exposureLevel'),
        (Get-MachineJsonElementScalarValue -Element $MachineElement -Name 'deviceValue'),
        (Get-MachineJsonElementScalarValue -Element $MachineElement -Name 'managedBy'),
        (Get-MachineJsonElementScalarValue -Element $MachineElement -Name 'isAadJoined'),
        (Get-MachineJsonElementScalarValue -Element $MachineElement -Name 'lastSeen'),
        (Get-MachineJsonElementScalarValue -Element $MachineElement -Name 'firstSeen'),
        (Get-MachineJsonElementScalarValue -Element $MachineElement -Name 'osVersion'),
        (Get-MachineJsonElementScalarValue -Element $MachineElement -Name 'computerDnsName'),
        (Get-MachineJsonElementScalarValue -Element $MachineElement -Name 'rbacGroupName'),
        (Get-MachineJsonElementScalarValue -Element $MachineElement -Name 'osPlatform'),
        @(Get-MachineJsonElementStringArrayValue -Element $MachineElement -Name 'machineTags')
    )

    $hasTupleValue = $false
    foreach ($value in $tuple) {
        if ($null -ne $value) {
            $hasTupleValue = $true
            break
        }
    }

    return [PSCustomObject]@{
        id = $machineId
        removed = $false
        tuple = if ($hasTupleValue) { $tuple } else { $null }
    }
}

function Read-MachineNormalizationEntriesFromFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $readContext = Open-JsonFileReadContext -Path $Path
    try {
        if ($readContext.Mode -eq 'Empty') {
            return
        }

        if ($readContext.Mode -eq 'Array') {
            $rawContent = Read-JsonFileRemainingContent -Context $readContext
            if ([string]::IsNullOrWhiteSpace($rawContent)) {
                return
            }

            $jsonDocument = [System.Text.Json.JsonDocument]::Parse($rawContent)
            $rawContent = $null
            try {
                if ($jsonDocument.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Array) {
                    return
                }

                foreach ($machineElement in $jsonDocument.RootElement.EnumerateArray()) {
                    $entry = ConvertFrom-MachineJsonElementToNormalizationEntry -MachineElement $machineElement
                    if ($null -ne $entry) {
                        $entry
                    }
                }
            }
            finally {
                $jsonDocument.Dispose()
            }

            return
        }

        $isFirstLine = [ref]$true
        while (-not $readContext.Reader.EndOfStream) {
            $line = Read-JsonFileLine -Context $readContext -IsFirstLine $isFirstLine
            if ([string]::IsNullOrWhiteSpace($line)) { continue }

            $jsonDocument = $null
            try {
                $jsonDocument = [System.Text.Json.JsonDocument]::Parse($line)
            }
            catch {
                Write-Warning "Failed to parse machine line in $(Split-Path -Leaf $Path): $_"
                continue
            }

            try {
                $entry = ConvertFrom-MachineJsonElementToNormalizationEntry -MachineElement $jsonDocument.RootElement
                if ($null -ne $entry) {
                    $entry
                }
            }
            finally {
                if ($null -ne $jsonDocument) {
                    $jsonDocument.Dispose()
                }
            }
        }
    }
    finally {
        Close-JsonFileReadContext -Context $readContext
    }
}

function Get-NormalizedMachineTag {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Tags
    )

    $tagList = [System.Collections.Generic.List[string]]::new()

    if ($null -eq $Tags) {
        return [string[]]@()
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
        return [string[]]@()
    }

    return [string[]]@($tagList | Sort-Object -Unique)
}

function Get-MachineCurrentPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    return Join-Path -Path $BasePath -ChildPath $Script:MachineCurrentFileName
}

function Get-MachineHistoryPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    return Join-Path -Path $BasePath -ChildPath $Script:MachineHistoryFileName
}

function Get-MachineHistoryQuarterlyPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $true)]
        [string]$PeriodKey
    )

    return Join-Path -Path $BasePath -ChildPath ([string]::Format($Script:MachineHistoryQuarterlyFileNamePattern, $PeriodKey))
}

function Test-IsMachineHistoryQuarterlyFileName {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    return ($Name -match '^Machines_History_\d{4}Q[1-4]\.json\.gz$')
}

function Test-IsMachineHistorySegmentFileName {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    return ($Name -match '^Machines_History_\d{8}T\d{6}Z_[a-f0-9]{8}\.json\.gz$')
}

function New-MachineHistorySegmentFileName {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $timestamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $suffix = [guid]::NewGuid().ToString('N').Substring(0, 8)
    return "Machines_History_${timestamp}_${suffix}.json.gz"
}

function Get-MachineHistoryQuarterlyFiles {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    [OutputType([System.IO.FileInfo[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    return [System.IO.FileInfo[]]@(
        Get-ChildItem -Path $BasePath -Filter 'Machines_History_*.json.gz' -File -ErrorAction SilentlyContinue |
            Where-Object { Test-IsMachineHistoryQuarterlyFileName -Name $_.Name } |
            Sort-Object Name
    )
}

function Get-MachineHistorySegmentFiles {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    [OutputType([System.IO.FileInfo[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    return [System.IO.FileInfo[]]@(
        Get-ChildItem -Path $BasePath -Filter 'Machines_History_*.json.gz' -File -ErrorAction SilentlyContinue |
            Where-Object { Test-IsMachineHistorySegmentFileName -Name $_.Name } |
            Sort-Object Name
    )
}

function Get-MachineHistoryAllSourcePaths {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    $paths = [System.Collections.Generic.List[string]]::new()
    $historyPath = Get-MachineHistoryPath -BasePath $BasePath
    $legacyHistoryPath = Get-LegacyCanonicalPath -Path $historyPath

    foreach ($file in Get-MachineHistoryQuarterlyFiles -BasePath $BasePath) {
        $paths.Add($file.FullName)
    }

    if (Test-Path -Path $historyPath -PathType Leaf) {
        $paths.Add($historyPath)
    }
    elseif (Test-Path -Path $legacyHistoryPath -PathType Leaf) {
        $paths.Add($legacyHistoryPath)
    }

    foreach ($file in Get-MachineHistorySegmentFiles -BasePath $BasePath) {
        $paths.Add($file.FullName)
    }

    return [string[]]@($paths)
}

function Get-MachineHistorySourcePaths {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    $quarterlyFiles = @(Get-MachineHistoryQuarterlyFiles -BasePath $BasePath)
    if ($quarterlyFiles.Count -gt 0) {
        return [string[]]@($quarterlyFiles | ForEach-Object { $_.FullName })
    }

    return (Get-MachineHistoryAllSourcePaths -BasePath $BasePath)
}

function Get-AdvancedHuntingCurrentPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    return Join-Path -Path $BasePath -ChildPath $Script:AdvancedHuntingCurrentFileName
}

function Get-NvdCveCurrentPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    return Join-Path -Path $BasePath -ChildPath $Script:NvdCveCurrentFileName
}

function Get-LegacyCanonicalPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ($Path.EndsWith('.gz', [System.StringComparison]::OrdinalIgnoreCase)) {
        return $Path.Substring(0, $Path.Length - 3)
    }

    return "$Path.gz"
}

function Test-IsLegacyMachineSnapshotFileName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    return ($Name -match '^Machines_\d{4}-\d{2}-\d{2}\.json$')
}

function Test-IsLegacyAdvancedHuntingSnapshotFileName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    return ($Name -match '^AdvancedHunting_\d+_\d{4}-\d{2}-\d{2}\.json$')
}

function Read-TextFileContent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ($Path.EndsWith('.gz', [System.StringComparison]::OrdinalIgnoreCase)) {
        return (Read-GzipTextFile -Path $Path)
    }

    return (Get-Content -Path $Path -Raw)
}

function Open-JsonFileReadContext {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $fileStream = $null
    $contentStream = $null
    $reader = $null
    try {
        $fileStream = [System.IO.File]::OpenRead($Path)
        $contentStream = if ($Path.EndsWith('.gz', [System.StringComparison]::OrdinalIgnoreCase)) {
            [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Decompress)
        }
        else {
            $fileStream
        }

        $reader = [System.IO.StreamReader]::new($contentStream, [System.Text.Encoding]::UTF8, $true)
        $mode = 'Empty'
        $firstContentText = $null
        while (-not $reader.EndOfStream) {
            $charValue = $reader.Read()
            if ($charValue -lt 0) {
                break
            }

            $char = [char]$charValue
            if (-not [char]::IsWhiteSpace($char)) {
                $mode = if ($char -eq '[') { 'Array' } else { 'Ndjson' }
                $firstContentText = [string]$char
                break
            }
        }

        $context = [PSCustomObject]@{
            Path = $Path
            Mode = $mode
            Reader = $reader
            ContentStream = $contentStream
            FileStream = $fileStream
            FirstContentText = $firstContentText
        }

        $reader = $null
        $contentStream = $null
        $fileStream = $null
        return $context
    }
    finally {
        if ($null -ne $reader) {
            $reader.Dispose()
        }
        elseif ($null -ne $contentStream -and $contentStream -ne $fileStream) {
            $contentStream.Dispose()
        }

        if ($null -ne $fileStream) {
            $fileStream.Dispose()
        }
    }
}

function Close-JsonFileReadContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Context
    )

    if ($null -eq $Context) {
        return
    }

    $reader = $Context.PSObject.Properties['Reader']?.Value
    if ($null -ne $reader) {
        $reader.Dispose()
        return
    }

    $contentStream = $Context.PSObject.Properties['ContentStream']?.Value
    $fileStream = $Context.PSObject.Properties['FileStream']?.Value
    if ($null -ne $contentStream -and $contentStream -ne $fileStream) {
        $contentStream.Dispose()
    }

    if ($null -ne $fileStream) {
        $fileStream.Dispose()
    }
}

function Read-JsonFileRemainingContent {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        $Context
    )

    if ($null -eq $Context -or $Context.Mode -eq 'Empty') {
        return $null
    }

    $builder = [System.Text.StringBuilder]::new()
    if (-not [string]::IsNullOrEmpty([string]$Context.FirstContentText)) {
        [void]$builder.Append([string]$Context.FirstContentText)
    }

    [void]$builder.Append($Context.Reader.ReadToEnd())
    return $builder.ToString()
}

function Read-JsonFileLine {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        $Context,

        [Parameter(Mandatory = $true)]
        [ref]$IsFirstLine
    )

    $line = $Context.Reader.ReadLine()
    if ($null -eq $line) {
        return $null
    }

    if ($IsFirstLine.Value) {
        $IsFirstLine.Value = $false
        if (-not [string]::IsNullOrEmpty([string]$Context.FirstContentText)) {
            return ([string]$Context.FirstContentText + $line)
        }
    }

    return $line
}

function Read-MachineRecordsFromFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $readContext = Open-JsonFileReadContext -Path $Path
    try {
        if ($readContext.Mode -eq 'Empty') {
            return
        }

        if ($readContext.Mode -eq 'Array') {
            $rawContent = Read-JsonFileRemainingContent -Context $readContext
            if ([string]::IsNullOrWhiteSpace($rawContent)) {
                return
            }

            $jsonDocument = [System.Text.Json.JsonDocument]::Parse($rawContent)
            $rawContent = $null
            try {
                if ($jsonDocument.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Array) {
                    return
                }

                foreach ($machineElement in $jsonDocument.RootElement.EnumerateArray()) {
                    $record = ConvertFrom-MachineJsonElementToCompactMachineRecord -MachineElement $machineElement
                    if ($null -ne $record) {
                        $record
                    }
                }
            }
            finally {
                $jsonDocument.Dispose()
            }

            return
        }

        $isFirstLine = [ref]$true
        while (-not $readContext.Reader.EndOfStream) {
            $line = Read-JsonFileLine -Context $readContext -IsFirstLine $isFirstLine
            if ([string]::IsNullOrWhiteSpace($line)) { continue }

            $jsonDocument = $null
            try {
                $jsonDocument = [System.Text.Json.JsonDocument]::Parse($line)
            }
            catch {
                Write-Warning "Failed to parse machine line in $(Split-Path -Leaf $Path): $_"
                continue
            }

            try {
                $record = ConvertFrom-MachineJsonElementToCompactMachineRecord -MachineElement $jsonDocument.RootElement
                if ($null -ne $record) {
                    $record
                }
            }
            finally {
                if ($null -ne $jsonDocument) {
                    $jsonDocument.Dispose()
                }
            }
        }
    }
    finally {
        Close-JsonFileReadContext -Context $readContext
    }
}

function Get-MachineStateHash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Machine
    )

    $state = [ordered]@{
        computerDnsName       = $Machine.PSObject.Properties['computerDnsName']?.Value
        rbacGroupName         = $Machine.PSObject.Properties['rbacGroupName']?.Value
        osPlatform            = $Machine.PSObject.Properties['osPlatform']?.Value
        osVersion             = $Machine.PSObject.Properties['osVersion']?.Value
        machineTags           = @(Get-NormalizedMachineTag -Tags $Machine.PSObject.Properties['machineTags']?.Value)
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
    if (-not (Get-Variable -Name _sha256 -Scope Script -ErrorAction Ignore)) {
        $Script:_sha256 = [System.Security.Cryptography.SHA256]::Create()
    }
    $hashBytes = $Script:_sha256.ComputeHash($bytes)
    return ([System.BitConverter]::ToString($hashBytes)).Replace('-', '').ToLowerInvariant()
}

function New-MachineSnapshotRecord {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Machine,

        [Parameter(Mandatory = $true)]
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

function New-MachineRemovalRecord {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MachineId,

        [Parameter(Mandatory = $true)]
        [string]$ObservedOn
    )

    return [PSCustomObject]@{
        id = $MachineId
        observedOn = $ObservedOn
        removed = $true
        stateHash = 'removed'
    }
}

function Write-NdjsonRecordsFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [System.Collections.IEnumerable]$Records
    )

    $fileStream = $null
    $gzipStream = $null
    $writer = $null
    $jsonWriter = $null
    try {
        if ($Path.EndsWith('.gz', [System.StringComparison]::OrdinalIgnoreCase)) {
            $fileStream = [System.IO.File]::Create($Path)
            $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Compress)
            $writer = [System.IO.StreamWriter]::new($gzipStream, [System.Text.UTF8Encoding]::new($false))
        }
        else {
            $writer = [System.IO.StreamWriter]::new($Path, $false, [System.Text.UTF8Encoding]::new($false))
        }

        $jsonWriter = [Newtonsoft.Json.JsonTextWriter]::new($writer)
        $jsonWriter.Formatting = [Newtonsoft.Json.Formatting]::None

        foreach ($record in $Records) {
            if ($null -eq $record) { continue }

            Write-JsonValueToWriter -Writer $jsonWriter -Value $record
            $jsonWriter.Flush()
            $writer.WriteLine()
        }
    }
    finally {
        if ($jsonWriter) { $jsonWriter.Close() }
        elseif ($writer) { $writer.Dispose() }
        elseif ($gzipStream) { $gzipStream.Dispose() }
        elseif ($fileStream) { $fileStream.Dispose() }
    }
}

function Get-MachineHistoryRecordKey {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        $Record
    )

    $id = [string]$Record.PSObject.Properties['id']?.Value
    $observedOn = Convert-ToYmdDate -DateValue $Record.PSObject.Properties['observedOn']?.Value
    $removed = if ($Record.PSObject.Properties['removed']?.Value -eq $true) { '1' } else { '0' }
    $stateHash = [string]$Record.PSObject.Properties['stateHash']?.Value
    return ($id + '|' + $observedOn + '|' + $removed + '|' + $stateHash)
}

function Add-MachineHistoryRecordToPeriodMap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$HistoryRecordsByPeriod,

        [Parameter(Mandatory = $true)]
        $RecordKeys,

        [Parameter(Mandatory = $true)]
        $Record
    )

    if ($null -eq $Record) { return }

    $id = [string]$Record.PSObject.Properties['id']?.Value
    if ([string]::IsNullOrWhiteSpace($id)) { return }

    $observedOn = Convert-ToYmdDate -DateValue $Record.PSObject.Properties['observedOn']?.Value
    if ([string]::IsNullOrWhiteSpace($observedOn)) { return }

    if (($Record.PSObject.Properties['removed']?.Value -ne $true) -and -not $Record.PSObject.Properties['stateHash']) {
        Add-Member -InputObject $Record -NotePropertyName stateHash -NotePropertyValue (Get-MachineStateHash -Machine $Record) -Force
    }

    if (-not $Record.PSObject.Properties['observedOn']) {
        Add-Member -InputObject $Record -NotePropertyName observedOn -NotePropertyValue $observedOn -Force
    }

    $recordKey = Get-MachineHistoryRecordKey -Record $Record
    if (-not $RecordKeys.Add($recordKey)) { return }

    $periodKey = Get-QuarterPeriodKeyFromDate -Date $observedOn
    if (-not $HistoryRecordsByPeriod.ContainsKey($periodKey)) {
        $HistoryRecordsByPeriod[$periodKey] = [System.Collections.Generic.List[object]]::new()
    }

    $HistoryRecordsByPeriod[$periodKey].Add($Record)
}

function Get-MachineHistoryRemovePaths {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.HashSet[string]]$PublishedHistoryNames
    )

    $removePaths = [System.Collections.Generic.List[string]]::new()
    foreach ($path in @(
        Get-ChildItem -Path $BasePath -Filter 'Machines_History*.json.gz' -File -ErrorAction SilentlyContinue |
            Where-Object { -not $PublishedHistoryNames.Contains($_.Name) } |
            ForEach-Object { $_.FullName }
    )) {
        $removePaths.Add($path)
    }

    $legacyHistoryJsonPath = Get-MachineHistoryPath -BasePath $BasePath
    $legacyHistoryGzipPath = Get-LegacyCanonicalPath -Path $legacyHistoryJsonPath
    foreach ($path in @($legacyHistoryJsonPath, $legacyHistoryGzipPath)) {
        if ([string]::IsNullOrWhiteSpace($path)) { continue }
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
        if ($removePaths -contains $path) { continue }
        $removePaths.Add($path)
    }

    return [string[]]@($removePaths)
}

function Add-InitializedMachineRecordToCurrentMap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$CurrentRecords,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [psobject]$Record,

        [Parameter(Mandatory = $true)]
        [string]$DefaultObservedOn
    )

    if ($null -eq $Record) { return }

    $properties = $Record.PSObject.Properties
    $machineId = [string]$properties['id']?.Value
    if ([string]::IsNullOrWhiteSpace($machineId)) { return }

    if ($properties['removed']?.Value -eq $true) {
        $CurrentRecords.Remove($machineId)
        return
    }

    if ($null -eq $properties['stateHash']) {
        $properties.Add([System.Management.Automation.PSNoteProperty]::new('stateHash', (Get-MachineStateHash -Machine $Record)))
    }

    if ($null -eq $properties['observedOn']) {
        $properties.Add([System.Management.Automation.PSNoteProperty]::new('observedOn', $DefaultObservedOn))
    }

    $CurrentRecords[$machineId] = $Record
}

function Initialize-MachineHistoryStore {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [switch]$RemoveLegacyFiles
    )

    $currentPath = Get-MachineCurrentPath -BasePath $Path
    $legacyCurrentPath = Get-LegacyCanonicalPath -Path $currentPath
    $currentReadPath = if (Test-Path -Path $currentPath) { $currentPath } elseif (Test-Path -Path $legacyCurrentPath) { $legacyCurrentPath } else { $null }
    $historySourcePaths = @(Get-MachineHistoryAllSourcePaths -BasePath $Path)
    $legacyFiles = @(Get-ChildItem -Path $Path -Filter 'Machines_*.json' -File | Where-Object { Test-IsLegacyMachineSnapshotFileName -Name $_.Name } | Sort-Object Name)
    $currentRecords = @{}
    $migratedLegacy = $false
    $historyRecordsByPeriod = @{}
    $historyRecordKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $defaultObservedOn = Get-Date -Format 'yyyy-MM-dd'

    foreach ($sourcePath in $historySourcePaths) {
        foreach ($record in Read-MachineRecordsFromFile -Path $sourcePath) {
            Add-MachineHistoryRecordToPeriodMap -HistoryRecordsByPeriod $historyRecordsByPeriod -RecordKeys $historyRecordKeys -Record $record
        }
    }

    if ($null -ne $currentReadPath) {
        foreach ($record in Read-MachineRecordsFromFile -Path $currentReadPath) {
            Add-InitializedMachineRecordToCurrentMap -CurrentRecords $currentRecords -Record $record -DefaultObservedOn $defaultObservedOn
        }
    } elseif ($historySourcePaths.Count -gt 0) {
        foreach ($sourcePath in $historySourcePaths) {
            foreach ($record in Read-MachineRecordsFromFile -Path $sourcePath) {
                Add-InitializedMachineRecordToCurrentMap -CurrentRecords $currentRecords -Record $record -DefaultObservedOn $defaultObservedOn
            }
        }
    }

    if ($legacyFiles.Count -gt 0) {
        foreach ($file in $legacyFiles) {
            $observedOn = [regex]::Match($file.Name, '\d{4}-\d{2}-\d{2}').Value
            foreach ($record in Read-MachineRecordsFromFile -Path $file.FullName) {
                if (-not $record.id) { continue }
                $snapshot = New-MachineSnapshotRecord -Machine $record -ObservedOn $observedOn
                $existing = $currentRecords[$snapshot.id]
                if (($null -eq $existing) -or ($existing.stateHash -ne $snapshot.stateHash)) {
                    Add-MachineHistoryRecordToPeriodMap -HistoryRecordsByPeriod $historyRecordsByPeriod -RecordKeys $historyRecordKeys -Record $snapshot
                }
                $currentRecords[$snapshot.id] = $snapshot
            }
        }
        if ($RemoveLegacyFiles) {
            Remove-Item -Path $legacyFiles.FullName -Force -ErrorAction SilentlyContinue
        }
        $migratedLegacy = $true
    }

    if (($historyRecordsByPeriod.Count -eq 0) -and $currentRecords.Count -gt 0) {
        foreach ($record in $currentRecords.Values) {
            Add-MachineHistoryRecordToPeriodMap -HistoryRecordsByPeriod $historyRecordsByPeriod -RecordKeys $historyRecordKeys -Record $record
        }
    }

    if ($migratedLegacy -and (Test-Path -Path $legacyCurrentPath)) {
        Remove-Item -Path $legacyCurrentPath -Force -ErrorAction SilentlyContinue
    }

    return @{
        CurrentPath           = $currentPath
        CurrentRecords        = $currentRecords
        HistoryRecordsByPeriod = $historyRecordsByPeriod
        MigratedLegacy        = $migratedLegacy
    }
}

function Convert-ToYmdDate {
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

    if ($raw.Length -ge 10 -and $raw[4] -eq '-' -and $raw[7] -eq '-') {
        return $raw.Substring(0, 10)
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

function Get-VendorMatchKey {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Vendor
    )

    if ([string]::IsNullOrWhiteSpace($Vendor)) {
        return ''
    }

    $trimmed = $Vendor.Trim()
    if ($env:DEFENDER_REPORTING_NORMALIZE_VENDOR_MATCH -ne '1') {
        return $trimmed
    }

    $normalized = $trimmed.ToLowerInvariant()
    $normalized = [regex]::Replace($normalized, '[^a-z0-9]+', ' ')
    $normalized = [regex]::Replace($normalized, '\b(corporation|corp|incorporated|inc|llc|ltd|limited|company|co|gmbh|ag|plc|pte)\b', ' ')
    $normalized = [regex]::Replace($normalized, '\s+', ' ').Trim()
    return $normalized
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

function Get-AdvancedHuntingInventoryMatchKey {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$DeviceId,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$SoftwareVendor,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$SoftwareName,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$SoftwareVersion
    )

    if ([string]::IsNullOrWhiteSpace($DeviceId) -or [string]::IsNullOrWhiteSpace($SoftwareName)) {
        return $null
    }

    return @(
        [string]$DeviceId
        [string]($SoftwareVendor ?? '')
        [string]$SoftwareName
        [string]($SoftwareVersion ?? '')
    ) -join '|'
}

function Get-AdvancedHuntingRecordType {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Record
    )

    $explicitRecordType = [string]$Record.PSObject.Properties['RecordType']?.Value
    switch ($explicitRecordType) {
        'Cve' { return 'Cve' }
        'DeviceUsers' { return 'DeviceUsers' }
        'Inventory' { return 'Inventory' }
    }

    $cveId = [string]$Record.PSObject.Properties['CveId']?.Value
    if (-not [string]::IsNullOrWhiteSpace($cveId)) {
        return 'Cve'
    }

    $deviceId = [string]$Record.PSObject.Properties['DeviceId']?.Value
    if (-not [string]::IsNullOrWhiteSpace($deviceId) -and $null -ne $Record.PSObject.Properties['LoggedOnUsers']) {
        return 'DeviceUsers'
    }

    if (
        -not [string]::IsNullOrWhiteSpace($deviceId) -and
        -not [string]::IsNullOrWhiteSpace([string]$Record.PSObject.Properties['SoftwareName']?.Value) -and
        (
            -not [string]::IsNullOrWhiteSpace([string]$Record.PSObject.Properties['ProductCodeCpe']?.Value) -or
            -not [string]::IsNullOrWhiteSpace([string]$Record.PSObject.Properties['EndOfSupportStatus']?.Value) -or
            -not [string]::IsNullOrWhiteSpace([string]$Record.PSObject.Properties['EndOfSupportDate']?.Value)
        )
    ) {
        return 'Inventory'
    }

    return $null
}

function Get-AdvancedHuntingStoreKey {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Record
    )

    $recordType = Get-AdvancedHuntingRecordType -Record $Record
    switch ($recordType) {
        'Cve' {
            $cveId = [string]$Record.PSObject.Properties['CveId']?.Value
            if (-not [string]::IsNullOrWhiteSpace($cveId)) {
                return ('Cve|' + $cveId)
            }
        }
        'DeviceUsers' {
            $deviceId = [string]$Record.PSObject.Properties['DeviceId']?.Value
            if (-not [string]::IsNullOrWhiteSpace($deviceId)) {
                return ('DeviceUsers|' + $deviceId)
            }
        }
        'Inventory' {
            $inventoryKey = Get-AdvancedHuntingInventoryMatchKey `
                -DeviceId ([string]$Record.PSObject.Properties['DeviceId']?.Value) `
                -SoftwareVendor ([string]$Record.PSObject.Properties['SoftwareVendor']?.Value) `
                -SoftwareName ([string]$Record.PSObject.Properties['SoftwareName']?.Value) `
                -SoftwareVersion ([string]$Record.PSObject.Properties['SoftwareVersion']?.Value)
            if (-not [string]::IsNullOrWhiteSpace($inventoryKey)) {
                return ('Inventory|' + $inventoryKey)
            }
        }
    }

    return $null
}

function Read-AdvancedHuntingRecordsFromFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $readContext = Open-JsonFileReadContext -Path $Path
    try {
        if ($readContext.Mode -eq 'Empty') {
            return
        }

        if ($readContext.Mode -eq 'Array') {
            $rawContent = Read-JsonFileRemainingContent -Context $readContext
            if ([string]::IsNullOrWhiteSpace($rawContent)) {
                return
            }

            $records = $rawContent | ConvertFrom-Json
            $rawContent = $null
            if ($null -eq $records) { return }
            if ($records -isnot [System.Array]) { $records = @($records) }

            foreach ($record in $records) {
                if ($null -ne $record) {
                    $record
                }
            }

            return
        }

        $isFirstLine = [ref]$true
        while (-not $readContext.Reader.EndOfStream) {
            $line = Read-JsonFileLine -Context $readContext -IsFirstLine $isFirstLine
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            try {
                $record = $line | ConvertFrom-Json
                if ($null -ne $record) { $record }
            }
            catch {
                Write-Warning "Failed to parse Advanced Hunting line in $(Split-Path -Leaf $Path): $_"
            }
        }
    }
    finally {
        Close-JsonFileReadContext -Context $readContext
    }
}

function Initialize-AdvancedHuntingStore {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [switch]$RemoveLegacyFiles
    )

    $currentPath = Get-AdvancedHuntingCurrentPath -BasePath $Path
    $legacyCurrentPath = Get-LegacyCanonicalPath -Path $currentPath
    $currentRecords = @{}
    $migratedLegacy = $false
    $legacyFiles = @(Get-ChildItem -Path $Path -Filter 'AdvancedHunting_*.json' -File | Where-Object { Test-IsLegacyAdvancedHuntingSnapshotFileName -Name $_.Name } | Sort-Object Name)

    if (Test-Path -Path $currentPath) {
        foreach ($record in Read-AdvancedHuntingRecordsFromFile -Path $currentPath) {
            $storeKey = Get-AdvancedHuntingStoreKey -Record $record
            if ($storeKey) {
                $currentRecords[$storeKey] = $record
            }
        }
    }
    elseif (Test-Path -Path $legacyCurrentPath) {
        foreach ($record in Read-AdvancedHuntingRecordsFromFile -Path $legacyCurrentPath) {
            $storeKey = Get-AdvancedHuntingStoreKey -Record $record
            if ($storeKey) {
                $currentRecords[$storeKey] = $record
            }
        }
        $migratedLegacy = $true
    }

    if ($legacyFiles.Count -gt 0) {
        foreach ($file in $legacyFiles) {
            $fallbackDate = [regex]::Match($file.Name, '\d{4}-\d{2}-\d{2}').Value
            foreach ($record in Read-AdvancedHuntingRecordsFromFile -Path $file.FullName) {
                $storeKey = Get-AdvancedHuntingStoreKey -Record $record
                if (-not $storeKey) { continue }

                $incomingKey = Get-AdvancedHuntingLastModifiedKey -LastModifiedTime $record.PSObject.Properties['LastModifiedTime']?.Value -FallbackDate $fallbackDate
                $existing = $currentRecords[$storeKey]

                if ($null -eq $existing) {
                    $currentRecords[$storeKey] = $record
                    $migratedLegacy = $true
                    continue
                }

                $existingKey = Get-AdvancedHuntingLastModifiedKey -LastModifiedTime $existing.PSObject.Properties['LastModifiedTime']?.Value -FallbackDate ''
                if ([string]::CompareOrdinal($incomingKey, $existingKey) -gt 0) {
                    $currentRecords[$storeKey] = $record
                    $migratedLegacy = $true
                }
            }
        }

        if ($migratedLegacy) {
            $stageRoot = Join-Path $Path ('.advancedhunting-store-staging-' + [guid]::NewGuid().ToString('N'))
            [void](New-Item -Path $stageRoot -ItemType Directory -Force)
            try {
                $stagedCurrentPath = Join-Path $stageRoot (Split-Path -Leaf $currentPath)
                Write-NdjsonRecordsFile -Path $stagedCurrentPath -Records $currentRecords.Values
                $removePaths = if ($RemoveLegacyFiles -and $currentRecords.Count -gt 0) {
                    @($legacyFiles.FullName) + @(
                        if (Test-Path -Path $legacyCurrentPath) { $legacyCurrentPath }
                    )
                }
                else {
                    @()
                }

                Publish-StoreFilesTransactional -BasePath $Path -StoreName 'advancedhunting' -Files @([PSCustomObject]@{
                    StagePath = $stagedCurrentPath
                    TargetPath = $currentPath
                }) -RemovePaths $removePaths
            }
            finally {
                if (Test-Path -Path $stageRoot) {
                    Remove-Item -Path $stageRoot -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }

    return @{
        CurrentPath    = $currentPath
        CurrentRecords = $currentRecords
        MigratedLegacy = $migratedLegacy
    }
}
