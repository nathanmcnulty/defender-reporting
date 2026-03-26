# Shared generator/runbook helpers used for dashboard normalization and HTML assembly.

function Get-JSLibrary {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [bool]$Critical = $false
    )

    Write-Information "Downloading $Name library..." -InformationAction Continue

    try {
        $response = Invoke-WebRequest -Uri $Url -TimeoutSec 30
        Write-Information "  $Name downloaded successfully" -InformationAction Continue
        return $response.Content
    }
    catch {
        $errorMessage = "Failed to download $Name from $Url`: $_"
        if ($Critical) {
            Write-Error $errorMessage
            throw
        }

        Write-Warning $errorMessage
        Write-Warning "Using fallback for $Name (PDF export may not work)"
        return "// $Name failed to load - functionality may be limited"
    }
}

function Save-JSLibraryFile {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [bool]$Critical = $false,

        [Parameter(Mandatory = $false)]
        [string]$CacheBasePath
    )

    $cachePath = $null
    if (-not [string]::IsNullOrWhiteSpace($CacheBasePath)) {
        $cacheDirectory = Get-DashboardCacheDirectory -BasePath $CacheBasePath -ChildPath 'libraries' -Create
        $urlHashBytes = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($Url))
        $urlHash = ([System.BitConverter]::ToString($urlHashBytes)).Replace('-', '').ToLowerInvariant().Substring(0, 16)
        $extension = [System.IO.Path]::GetExtension($OutputPath)
        if ([string]::IsNullOrWhiteSpace($extension)) {
            $extension = '.js'
        }

        $safeName = ($Name -replace '[^A-Za-z0-9._-]', '-')
        $cachePath = Join-Path $cacheDirectory ("{0}-{1}{2}" -f $safeName, $urlHash, $extension)
        if (Test-Path -LiteralPath $cachePath -PathType Leaf) {
            Copy-Item -LiteralPath $cachePath -Destination $OutputPath -Force
            Write-Information "Reusing cached $Name library" -InformationAction Continue
            return $OutputPath
        }
    }

    Write-Information "Downloading $Name library..." -InformationAction Continue

    try {
        Invoke-WebRequest -Uri $Url -OutFile $OutputPath -TimeoutSec 30
        if ($cachePath) {
            Copy-Item -LiteralPath $OutputPath -Destination $cachePath -Force
        }
        Write-Information "  $Name downloaded successfully" -InformationAction Continue
        return $OutputPath
    }
    catch {
        $errorMessage = "Failed to download $Name from $Url`: $_"
        if ($Critical) {
            Write-Error $errorMessage
            throw
        }

        Write-Warning $errorMessage
        return $null
    }
}

function Write-FileContent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.TextWriter]$Writer,

        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    $reader = [System.IO.StreamReader]::new($FilePath, [System.Text.Encoding]::UTF8)
    try {
        $buffer = New-Object char[] 8192
        while (($charsRead = $reader.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $Writer.Write($buffer, 0, $charsRead)
        }
    }
    finally {
        $reader.Dispose()
    }
}

function Compress-FileGzip {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$InputPath,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [System.IO.Compression.CompressionLevel]$CompressionLevel = [System.IO.Compression.CompressionLevel]::Fastest
    )

    $inputStream = $null
    $outputStream = $null
    $gzipStream = $null
    try {
        $inputStream = [System.IO.File]::OpenRead($InputPath)
        $outputStream = [System.IO.File]::Create($OutputPath)
        $gzipStream = [System.IO.Compression.GZipStream]::new($outputStream, $CompressionLevel)
        $inputStream.CopyTo($gzipStream)
    }
    finally {
        if ($gzipStream) { $gzipStream.Dispose() }
        elseif ($outputStream) { $outputStream.Dispose() }
        if ($inputStream) { $inputStream.Dispose() }
    }

    return $OutputPath
}

function Write-CombinedTextBundle {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$InputPaths,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $writer = [System.IO.StreamWriter]::new($OutputPath, $false, [System.Text.UTF8Encoding]::new($false))
    try {
        foreach ($inputPath in $InputPaths) {
            if ([string]::IsNullOrWhiteSpace($inputPath) -or -not (Test-Path -LiteralPath $inputPath -PathType Leaf)) {
                continue
            }

            Write-FileContent -Writer $writer -FilePath $inputPath
            $writer.WriteLine()
            $writer.WriteLine()
        }
    }
    finally {
        $writer.Dispose()
    }

    return $OutputPath
}

function Write-Base64FileContent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.TextWriter]$Writer,

        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    $stream = [System.IO.File]::OpenRead($FilePath)
    try {
        $buffer = New-Object byte[] 12288
        $carry = New-Object byte[] 2
        $carryCount = 0

        while (($bytesRead = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $totalCount = $carryCount + $bytesRead
            $workBuffer = New-Object byte[] $totalCount

            if ($carryCount -gt 0) {
                [System.Array]::Copy($carry, 0, $workBuffer, 0, $carryCount)
            }
            [System.Array]::Copy($buffer, 0, $workBuffer, $carryCount, $bytesRead)

            $encodableCount = $totalCount - ($totalCount % 3)
            if ($encodableCount -gt 0) {
                $Writer.Write([System.Convert]::ToBase64String($workBuffer, 0, $encodableCount))
            }

            $carryCount = $totalCount - $encodableCount
            if ($carryCount -gt 0) {
                [System.Array]::Copy($workBuffer, $encodableCount, $carry, 0, $carryCount)
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

function Write-JsonValueToWriter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Newtonsoft.Json.JsonTextWriter]$Writer,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        $Writer.WriteNull()
        return
    }

    if ($Value -is [System.Management.Automation.PSObject]) {
        $psProperties = @($Value.PSObject.Properties | Where-Object { $_.MemberType -eq [System.Management.Automation.PSMemberTypes]::NoteProperty })
        if ($psProperties.Count -gt 0) {
            $Writer.WriteStartObject()
            foreach ($property in $psProperties) {
                $Writer.WritePropertyName([string]$property.Name)
                Write-JsonValueToWriter -Writer $Writer -Value $property.Value
            }
            $Writer.WriteEndObject()
            return
        }

        $baseValue = $Value.BaseObject
        if ($null -ne $baseValue -and $baseValue -ne $Value) {
            Write-JsonValueToWriter -Writer $Writer -Value $baseValue
            return
        }
    }

    $typeCode = [System.Type]::GetTypeCode($Value.GetType())
    switch ($typeCode) {
        ([System.TypeCode]::Boolean) {
            $Writer.WriteValue([bool]$Value)
            return
        }
        ([System.TypeCode]::Byte) {
            $Writer.WriteValue([byte]$Value)
            return
        }
        ([System.TypeCode]::SByte) {
            $Writer.WriteValue([sbyte]$Value)
            return
        }
        ([System.TypeCode]::Int16) {
            $Writer.WriteValue([int16]$Value)
            return
        }
        ([System.TypeCode]::UInt16) {
            $Writer.WriteValue([uint16]$Value)
            return
        }
        ([System.TypeCode]::Int32) {
            $Writer.WriteValue([int]$Value)
            return
        }
        ([System.TypeCode]::UInt32) {
            $Writer.WriteValue([uint32]$Value)
            return
        }
        ([System.TypeCode]::Int64) {
            $Writer.WriteValue([long]$Value)
            return
        }
        ([System.TypeCode]::UInt64) {
            $Writer.WriteValue([uint64]$Value)
            return
        }
        ([System.TypeCode]::Single) {
            $Writer.WriteValue([single]$Value)
            return
        }
        ([System.TypeCode]::Double) {
            $Writer.WriteValue([double]$Value)
            return
        }
        ([System.TypeCode]::Decimal) {
            $Writer.WriteValue([decimal]$Value)
            return
        }
        ([System.TypeCode]::DateTime) {
            $Writer.WriteValue(([datetime]$Value).ToString('o'))
            return
        }
        ([System.TypeCode]::Char) {
            $Writer.WriteValue([string]$Value)
            return
        }
        ([System.TypeCode]::String) {
            $Writer.WriteValue([string]$Value)
            return
        }
    }

    if ($Value -is [System.Collections.IDictionary]) {
        $Writer.WriteStartObject()
        foreach ($key in $Value.Keys) {
            $Writer.WritePropertyName([string]$key)
            Write-JsonValueToWriter -Writer $Writer -Value $Value[$key]
        }
        $Writer.WriteEndObject()
        return
    }

    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $Writer.WriteStartArray()
        foreach ($item in $Value) {
            Write-JsonValueToWriter -Writer $Writer -Value $item
        }
        $Writer.WriteEndArray()
        return
    }

    $Writer.WriteValue($Value.ToString())
}

function Open-JsonArrayFileWriter {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $streamWriter = [System.IO.StreamWriter]::new($Path, $false, [System.Text.UTF8Encoding]::new($false))
    $jsonWriter = [Newtonsoft.Json.JsonTextWriter]::new($streamWriter)
    $jsonWriter.Formatting = [Newtonsoft.Json.Formatting]::None
    $jsonWriter.WriteStartArray()

    return [PSCustomObject]@{
        Path = $Path
        StreamWriter = $streamWriter
        JsonWriter = $jsonWriter
    }
}

function Write-JsonArrayFileValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$WriterState,

        [Parameter(Mandatory = $false)]
        $Value
    )

    Write-JsonValueToWriter -Writer $WriterState.JsonWriter -Value $Value
}

function Close-JsonArrayFileWriter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$WriterState
    )

    if ($WriterState.JsonWriter) {
        $WriterState.JsonWriter.WriteEndArray()
        $WriterState.JsonWriter.Flush()
        $WriterState.JsonWriter.Close()
        $WriterState.JsonWriter = $null
        $WriterState.StreamWriter = $null
        return
    }

    if ($WriterState.StreamWriter) {
        $WriterState.StreamWriter.Dispose()
        $WriterState.StreamWriter = $null
    }
}

function Write-CompactJsonArrayValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$WriterState,

        [Parameter(Mandatory = $false)]
        $Value
    )

    $writer = $WriterState.JsonWriter
    if ($null -eq $Value) {
        $writer.WriteNull()
        return
    }

    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $writer.WriteStartArray()
        foreach ($nestedValue in $Value) {
            if ($null -eq $nestedValue) {
                $writer.WriteNull()
            }
            else {
                $writer.WriteValue($nestedValue)
            }
        }
        $writer.WriteEndArray()
        return
    }

    $writer.WriteValue($Value)
}

function Write-CompactColumnFileValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$WriterState,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Value
    )

    if ($WriterState.PSObject.Properties['JsonWriter'] -and $WriterState.JsonWriter) {
        Write-CompactJsonArrayValue -WriterState $WriterState -Value $Value
        return
    }

    Add-CompactVulnColumnValue -ColumnState $WriterState -Value $Value
}

function Open-CompactVulnColumnWriterSet {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DirectoryPath
    )

    $null = New-Item -Path $DirectoryPath -ItemType Directory -Force
    $paths = [ordered]@{}
    $writers = @{}
    foreach ($columnName in @('d', 'c', 's', 'v', 'f', 'l', 'ua', 'u', 'dp', 'rp')) {
        $columnPath = Join-Path $DirectoryPath ($columnName + '.json')
        $streamWriter = [System.IO.StreamWriter]::new($columnPath, $false, [System.Text.UTF8Encoding]::new($false))
        $streamWriter.Write('[')
        $paths[$columnName] = $columnPath
        $writers[$columnName] = [PSCustomObject]@{
            Path = $columnPath
            StreamWriter = $streamWriter
            Buffer = [System.Text.StringBuilder]::new(131072)
            HasValue = $false
        }
    }

    return [PSCustomObject]@{
        DirectoryPath = $DirectoryPath
        Paths = $paths
        Writers = $writers
    }
}

function Write-CompactVulnRecordColumnSet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$WriterSet,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object[]]$Record
    )

    if ($null -eq $Record) {
        throw 'Compact vulnerability record cannot be null.'
    }

    Add-CompactVulnColumnValue -ColumnState $WriterSet.Writers.d -Value $Record[0]
    Add-CompactVulnColumnValue -ColumnState $WriterSet.Writers.c -Value $Record[1]
    Add-CompactVulnColumnValue -ColumnState $WriterSet.Writers.s -Value $Record[2]
    Add-CompactVulnColumnValue -ColumnState $WriterSet.Writers.v -Value $Record[3]
    Add-CompactVulnColumnValue -ColumnState $WriterSet.Writers.f -Value $Record[4]
    Add-CompactVulnColumnValue -ColumnState $WriterSet.Writers.l -Value $Record[5]
    Add-CompactVulnColumnValue -ColumnState $WriterSet.Writers.ua -Value $Record[6]
    Add-CompactVulnColumnValue -ColumnState $WriterSet.Writers.u -Value $Record[7]
    Add-CompactVulnColumnValue -ColumnState $WriterSet.Writers.dp -Value $Record[8]
    Add-CompactVulnColumnValue -ColumnState $WriterSet.Writers.rp -Value $Record[9]
}

function Add-CompactVulnColumnValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$ColumnState,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Value
    )

    $buffer = $ColumnState.Buffer
    if ($ColumnState.HasValue) {
        [void]$buffer.Append(',')
    }
    else {
        $ColumnState.HasValue = $true
    }

    if ($null -eq $Value) {
        [void]$buffer.Append('null')
    }
    elseif ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        [void]$buffer.Append('[')
        $isFirstNestedValue = $true
        foreach ($nestedValue in $Value) {
            if ($isFirstNestedValue) {
                $isFirstNestedValue = $false
            }
            else {
                [void]$buffer.Append(',')
            }

            if ($null -eq $nestedValue) {
                [void]$buffer.Append('null')
            }
            else {
                [void]$buffer.Append([string]$nestedValue)
            }
        }
        [void]$buffer.Append(']')
    }
    else {
        [void]$buffer.Append([string]$Value)
    }

    if ($buffer.Length -ge 131072) {
        $ColumnState.StreamWriter.Write($buffer.ToString())
        [void]$buffer.Clear()
    }
}

function Sync-CompactVulnColumnWriterSet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$WriterSet
    )

    foreach ($columnWriter in $WriterSet.Writers.Values) {
        if ($columnWriter.StreamWriter) {
            if ($columnWriter.Buffer.Length -gt 0) {
                $columnWriter.StreamWriter.Write($columnWriter.Buffer.ToString())
                [void]$columnWriter.Buffer.Clear()
            }
            $columnWriter.StreamWriter.Flush()
        }
    }
}

function Close-CompactVulnColumnWriterSet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$WriterSet
    )

    foreach ($columnWriter in $WriterSet.Writers.Values) {
        if ($columnWriter.StreamWriter) {
            if ($columnWriter.Buffer.Length -gt 0) {
                $columnWriter.StreamWriter.Write($columnWriter.Buffer.ToString())
                [void]$columnWriter.Buffer.Clear()
            }
            $columnWriter.StreamWriter.Write(']')
            $columnWriter.StreamWriter.Dispose()
            $columnWriter.StreamWriter = $null
        }
    }
}

function Read-CompactJsonReaderValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Newtonsoft.Json.JsonTextReader]$Reader
    )

    switch ($Reader.TokenType) {
        ([Newtonsoft.Json.JsonToken]::Null) { return $null }
        ([Newtonsoft.Json.JsonToken]::Integer) { return $Reader.Value }
        ([Newtonsoft.Json.JsonToken]::Float) { return $Reader.Value }
        ([Newtonsoft.Json.JsonToken]::String) { return $Reader.Value }
        ([Newtonsoft.Json.JsonToken]::Boolean) { return $Reader.Value }
        ([Newtonsoft.Json.JsonToken]::StartArray) {
            $values = [System.Collections.Generic.List[object]]::new()
            while ($Reader.Read()) {
                if ($Reader.TokenType -eq [Newtonsoft.Json.JsonToken]::EndArray) {
                    break
                }

                $values.Add((Read-CompactJsonReaderValue -Reader $Reader))
            }

            return @($values)
        }
        default {
            throw "Unsupported JSON token '$($Reader.TokenType)' while reading compact vulnerability payload."
        }
    }
}

function ConvertTo-VulnColumnFileSet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VulnsPath,

        [Parameter(Mandatory = $true)]
        [hashtable]$ColumnWriters
    )

    $reader = $null
    $jsonReader = $null

    try {
        $reader = [System.IO.StreamReader]::new($VulnsPath, [System.Text.Encoding]::UTF8)
        $jsonReader = [Newtonsoft.Json.JsonTextReader]::new($reader)

        if (-not $jsonReader.Read() -or $jsonReader.TokenType -ne [Newtonsoft.Json.JsonToken]::StartArray) {
            throw "Expected vulnerability payload '$VulnsPath' to start with a JSON array."
        }

        while ($jsonReader.Read()) {
            if ($jsonReader.TokenType -eq [Newtonsoft.Json.JsonToken]::EndArray) {
                break
            }

            if ($jsonReader.TokenType -ne [Newtonsoft.Json.JsonToken]::StartArray) {
                throw "Expected compact vulnerability row array in '$VulnsPath', found '$($jsonReader.TokenType)'."
            }

            $rowValues = New-Object object[] 10
            for ($fieldIndex = 0; $fieldIndex -lt 10; $fieldIndex++) {
                if (-not $jsonReader.Read()) {
                    throw "Unexpected end of vulnerability payload '$VulnsPath'."
                }

                $rowValues[$fieldIndex] = Read-CompactJsonReaderValue -Reader $jsonReader
            }

            if (-not $jsonReader.Read() -or $jsonReader.TokenType -ne [Newtonsoft.Json.JsonToken]::EndArray) {
                throw "Expected end of compact vulnerability row array in '$VulnsPath'."
            }

            Write-CompactColumnFileValue -WriterState $ColumnWriters.d -Value $rowValues[0]
            Write-CompactColumnFileValue -WriterState $ColumnWriters.c -Value $rowValues[1]
            Write-CompactColumnFileValue -WriterState $ColumnWriters.s -Value $rowValues[2]
            Write-CompactColumnFileValue -WriterState $ColumnWriters.v -Value $rowValues[3]
            Write-CompactColumnFileValue -WriterState $ColumnWriters.f -Value $rowValues[4]
            Write-CompactColumnFileValue -WriterState $ColumnWriters.l -Value $rowValues[5]
            Write-CompactColumnFileValue -WriterState $ColumnWriters.ua -Value $rowValues[6]
            Write-CompactColumnFileValue -WriterState $ColumnWriters.u -Value $rowValues[7]
            Write-CompactColumnFileValue -WriterState $ColumnWriters.dp -Value $rowValues[8]
            Write-CompactColumnFileValue -WriterState $ColumnWriters.rp -Value $rowValues[9]
        }
    }
    finally {
        if ($jsonReader) { $jsonReader.Close() }
        if ($reader) { $reader.Dispose() }
    }
}

function Write-CombinedPayloadGzip {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Lookups,

        [Parameter(Mandatory = $false)]
        [string]$VulnsPath,

        [Parameter(Mandatory = $false)]
        [hashtable]$VulnColumnPaths,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $fileStream = $null
    $gzipStream = $null
    $writer = $null
    $jsonWriter = $null
    $columnDirectory = $null
    $columnWriters = @{}
    $columnWriterSet = $null
    $columnReaders = [System.Collections.Generic.List[System.IDisposable]]::new()
    $activeColumnPaths = $null

    try {
        $fileStream = [System.IO.File]::Create($OutputPath)
        $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionLevel]::Fastest)
        $writer = [System.IO.StreamWriter]::new($gzipStream, [System.Text.UTF8Encoding]::new($false))
        $jsonWriter = [Newtonsoft.Json.JsonTextWriter]::new($writer)
        $jsonWriter.Formatting = [Newtonsoft.Json.Formatting]::None

        $jsonWriter.WriteStartObject()
        $jsonWriter.WritePropertyName('lookups')
        $jsonWriter.WriteStartObject()
        $lookupPropertyNames = @(
            'vendors',
            'severities',
            'exploitLevels',
            'groups',
            'platforms',
            'tags',
            'updates',
            'versions',
            'dates',
            'diskPaths',
            'regPaths',
            'affSoftware',
            'batchTitles',
            'devices',
            'software',
            'cves',
            'noTagsIdx'
        )
        foreach ($lookupPropertyName in $lookupPropertyNames) {
            $jsonWriter.WritePropertyName($lookupPropertyName)
            $lookupValue = $Lookups.PSObject.Properties[$lookupPropertyName].Value
            Write-JsonValueToWriter -Writer $jsonWriter -Value $lookupValue
        }
        $jsonWriter.WriteEndObject()

        if ($VulnColumnPaths) {
            $activeColumnPaths = $VulnColumnPaths
        }
        else {
            if ([string]::IsNullOrWhiteSpace($VulnsPath) -or -not (Test-Path -LiteralPath $VulnsPath -PathType Leaf)) {
                throw 'Write-CombinedPayloadGzip requires either -VulnsPath or -VulnColumnPaths.'
            }

            $columnDirectory = Join-Path ([System.IO.Path]::GetDirectoryName($OutputPath)) ('payload-columns-' + [System.Guid]::NewGuid().ToString('N'))
            $null = New-Item -Path $columnDirectory -ItemType Directory -Force

            foreach ($columnName in @('d', 'c', 's', 'v', 'f', 'l', 'ua', 'u', 'dp', 'rp')) {
                $columnWriters[$columnName] = Open-JsonArrayFileWriter -Path (Join-Path $columnDirectory ($columnName + '.json'))
            }
            ConvertTo-VulnColumnFileSet -VulnsPath $VulnsPath -ColumnWriters $columnWriters
            foreach ($columnWriter in $columnWriters.Values) {
                Close-JsonArrayFileWriter -WriterState $columnWriter
            }

            $activeColumnPaths = @{}
            foreach ($columnName in @('d', 'c', 's', 'v', 'f', 'l', 'ua', 'u', 'dp', 'rp')) {
                $activeColumnPaths[$columnName] = $columnWriters[$columnName].Path
            }
        }

        $jsonWriter.WritePropertyName('vulnsFormat')
        $jsonWriter.WriteValue('columns-v1')
        $jsonWriter.WritePropertyName('vulns')
        $jsonWriter.WriteStartObject()
        foreach ($columnName in @('d', 'c', 's', 'v', 'f', 'l', 'ua', 'u', 'dp', 'rp')) {
            $jsonWriter.WritePropertyName($columnName)
            $columnReader = [System.IO.StreamReader]::new([string]$activeColumnPaths[$columnName], [System.Text.Encoding]::UTF8)
            $columnJsonReader = [Newtonsoft.Json.JsonTextReader]::new($columnReader)
            [void]$columnReaders.Add($columnJsonReader)
            [void]$columnReaders.Add($columnReader)
            $jsonWriter.WriteToken($columnJsonReader)
        }
        $jsonWriter.WriteEndObject()

        $jsonWriter.WriteEndObject()
        $jsonWriter.Flush()
    }
    finally {
        foreach ($columnDisposable in $columnReaders) {
            $columnDisposable.Dispose()
        }
        if ($columnWriterSet) {
            try {
                Close-CompactVulnColumnWriterSet -WriterSet $columnWriterSet
            }
            catch {
                Write-Verbose ("Ignoring temporary compact column writer cleanup failure: {0}" -f $_.Exception.Message)
            }
        }
        else {
            foreach ($columnWriter in $columnWriters.Values) {
                if ($columnWriter.JsonWriter -or $columnWriter.StreamWriter) {
                    try {
                        Close-JsonArrayFileWriter -WriterState $columnWriter
                    }
                    catch {
                        Write-Verbose ("Ignoring temporary JSON array writer cleanup failure: {0}" -f $_.Exception.Message)
                    }
                }
            }
        }
        if ($columnDirectory -and (Test-Path -LiteralPath $columnDirectory -PathType Container)) {
            Remove-Item -LiteralPath $columnDirectory -Recurse -Force -ErrorAction SilentlyContinue
        }
        if ($jsonWriter) { $jsonWriter.Close() }
        elseif ($writer) { $writer.Dispose() }
        elseif ($gzipStream) { $gzipStream.Dispose() }
        elseif ($fileStream) { $fileStream.Dispose() }
    }
}

function Write-TemplatedHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Template,

        [Parameter(Mandatory = $true)]
        [array]$Segments,

        [Parameter(Mandatory = $true)]
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
            elseif ($segment.ContainsKey('FilePath')) {
                Write-FileContent -Writer $writer -FilePath $segment.FilePath
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

function Read-MachineData {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return Invoke-WithStoreLock -BasePath $Path -StoreName 'machines' -ScriptBlock {
        Restore-StoreTransaction -BasePath $Path -StoreName 'machines'

        Write-Information "Reading machine data from $Path..." -InformationAction Continue
        $machines = @{}

        $currentPath = Get-MachineCurrentPath -BasePath $Path
        $legacyCurrentPath = Get-LegacyCanonicalPath -Path $currentPath
        $currentReadPath = if (Test-Path -Path $currentPath) { $currentPath } elseif (Test-Path -Path $legacyCurrentPath) { $legacyCurrentPath } else { $null }
        $historySourcePaths = @(Get-MachineHistorySourcePaths -BasePath $Path)

        if ($null -ne $currentReadPath) {
            Write-Information "  Using $(Split-Path -Leaf $currentReadPath)" -InformationAction Continue
            foreach ($record in Read-MachineRecordsFromFile -Path $currentReadPath) {
                if ($record.id) {
                    if ($record.PSObject.Properties['removed']?.Value -eq $true) {
                        $machines.Remove($record.id)
                        continue
                    }
                    $machines[$record.id] = ConvertTo-CompactMachineRecord -Machine $record
                }
            }
        }
        elseif ($historySourcePaths.Count -gt 0) {
            Write-Information "  Reconstructing current state from $($historySourcePaths.Count) machine history source file(s)" -InformationAction Continue
            foreach ($sourcePath in $historySourcePaths) {
                foreach ($record in Read-MachineRecordsFromFile -Path $sourcePath) {
                    if ($record.id) {
                        if ($record.PSObject.Properties['removed']?.Value -eq $true) {
                            $machines.Remove($record.id)
                            continue
                        }
                        $machines[$record.id] = ConvertTo-CompactMachineRecord -Machine $record
                    }
                }
            }
        }
        else {
            $machineFiles = @(Get-ChildItem -Path $Path -Filter 'Machines_*.json' -File | Where-Object { Test-IsLegacyMachineSnapshotFileName -Name $_.Name } | Sort-Object Name -Descending)

            if ($machineFiles.Count -eq 0) {
                Write-Warning 'No machine data files found. Device details may be incomplete.'
                return @{}
            }

            Write-Information "  Found $($machineFiles.Count) legacy machine snapshot file(s)" -InformationAction Continue
            foreach ($file in $machineFiles) {
                Write-Information "  Processing $($file.Name)..." -InformationAction Continue
                foreach ($record in Read-MachineRecordsFromFile -Path $file.FullName) {
                    if ($record.id -and -not $machines.ContainsKey($record.id)) {
                        $machines[$record.id] = ConvertTo-CompactMachineRecord -Machine $record
                    }
                }
            }
        }

        Write-Information "  Loaded $($machines.Count) unique machines" -InformationAction Continue
        return $machines
    }
}

function Read-AdvancedHuntingData {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return Invoke-WithStoreLock -BasePath $Path -StoreName 'advancedhunting' -ScriptBlock {
        Restore-StoreTransaction -BasePath $Path -StoreName 'advancedhunting'

        Write-Information "Reading Advanced Hunting data from $Path..." -InformationAction Continue

        $ahData = @{}
        $parseErrors = 0
        $currentPath = Get-AdvancedHuntingCurrentPath -BasePath $Path
        $legacyCurrentPath = Get-LegacyCanonicalPath -Path $currentPath

        if ((-not (Test-Path -Path $currentPath)) -and (Test-Path -Path $legacyCurrentPath)) {
            $currentPath = $legacyCurrentPath
        }

        if (Test-Path -Path $currentPath) {
            Write-Information "  Using $(Split-Path -Leaf $currentPath)" -InformationAction Continue
            $sourceFiles = @(Get-Item -Path $currentPath)
        }
        else {
            $sourceFiles = @(Get-ChildItem -Path $Path -Filter 'AdvancedHunting_*.json' -File |
                Where-Object { Test-IsLegacyAdvancedHuntingSnapshotFileName -Name $_.Name } |
                Sort-Object Name -Descending)

            if ($sourceFiles.Count -eq 0) {
                Write-Warning 'No Advanced Hunting data files found. CVE enrichment will be skipped.'
                return @{}
            }

            Write-Information "  Found $($sourceFiles.Count) legacy Advanced Hunting file(s)" -InformationAction Continue
        }

        foreach ($file in $sourceFiles) {
            Write-Information "  Processing $($file.Name)..." -InformationAction Continue
            foreach ($record in Read-AdvancedHuntingRecordsFromFile -Path $file.FullName) {
                try {
                    $cveId = $record.CveId
                    if ($cveId -and -not $ahData.ContainsKey($cveId)) {
                        $pdRaw = $record.PSObject.Properties['PublishedDate']?.Value
                        $ahData[$cveId] = @{
                            PublishedDate = Convert-ToYmdDate -DateValue $pdRaw
                            VulnerabilityDescription = $record.PSObject.Properties['VulnerabilityDescription']?.Value
                            EpssScore = $record.PSObject.Properties['EpssScore']?.Value
                            AffectedSoftware = $record.PSObject.Properties['AffectedSoftware']?.Value
                        }
                    }
                }
                catch {
                    $parseErrors++
                    if ($parseErrors -le 5) {
                        Write-Warning "Failed to process Advanced Hunting record in $($file.Name): $_"
                    }
                }
            }
        }

        if ($parseErrors -gt 0) {
            Write-Warning "Total parse errors: $parseErrors"
        }

        Write-Information "  Loaded enrichment data for $($ahData.Count) unique CVEs" -InformationAction Continue
        return $ahData
    }
}

function Get-DashboardCacheDirectory {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $false)]
        [string]$ChildPath,

        [Parameter(Mandatory = $false)]
        [switch]$Create
    )

    $cachePath = Join-Path $BasePath '.dashboard-cache'
    if (-not [string]::IsNullOrWhiteSpace($ChildPath)) {
        $cachePath = Join-Path $cachePath $ChildPath
    }

    if ($Create) {
        [void](New-Item -Path $cachePath -ItemType Directory -Force)
    }

    return $cachePath
}

function Get-FileSha256Hex {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $fileStream = $null
    $sha256 = $null
    try {
        $fileStream = [System.IO.File]::OpenRead($Path)
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash($fileStream)
        return ([System.BitConverter]::ToString($hashBytes)).Replace('-', '').ToLowerInvariant()
    }
    finally {
        if ($sha256) { $sha256.Dispose() }
        if ($fileStream) { $fileStream.Dispose() }
    }
}

function Get-VulnObservedWindowCacheFingerprint {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 30)]
        [int]$AllowedGapDays = 1
    )

    $sourceFiles = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    if (Test-VulnContentStoreExistence -BasePath $BasePath) {
        foreach ($path in @(
                (Get-VulnContentDictionaryPath -BasePath $BasePath)
                (Get-VulnCurrentRefsPath -BasePath $BasePath)
            )) {
            if (Test-Path -LiteralPath $path -PathType Leaf) {
                $sourceFiles.Add((Get-Item -LiteralPath $path))
            }
        }

        foreach ($historyRefsFile in @(Get-ChildItem -Path $BasePath -Filter 'VulnHistoryRefs_*.json.gz' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
            $sourceFiles.Add($historyRefsFile)
        }
    }
    else {
        $currentPath = Get-VulnCurrentPath -BasePath $BasePath
        if (Test-Path -LiteralPath $currentPath -PathType Leaf) {
            $sourceFiles.Add((Get-Item -LiteralPath $currentPath))
        }

        foreach ($historyRowsFile in @(Get-ChildItem -Path $BasePath -Filter 'VulnHistoryRows_*.json.gz' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
            $sourceFiles.Add($historyRowsFile)
        }
    }

    if ($sourceFiles.Count -eq 0) {
        return $null
    }

    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.AppendLine('observed-window-cache-v1')
    [void]$builder.AppendLine(('AllowedGapDays=' + $AllowedGapDays))
    foreach ($file in @($sourceFiles | Sort-Object FullName -Unique)) {
        $hash = Get-FileSha256Hex -Path $file.FullName
        [void]$builder.Append($file.Name).Append('|')
        [void]$builder.Append($file.Length).Append('|')
        [void]$builder.Append($file.LastWriteTimeUtc.Ticks).Append('|')
        [void]$builder.AppendLine($hash)
    }

    $fingerprintBytes = [System.Text.Encoding]::UTF8.GetBytes($builder.ToString())
    $fingerprintHash = [System.Security.Cryptography.SHA256]::HashData($fingerprintBytes)
    return ([System.BitConverter]::ToString($fingerprintHash)).Replace('-', '').ToLowerInvariant()
}

function Get-VulnObservedWindowCachePath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $true)]
        [string]$Fingerprint,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 30)]
        [int]$AllowedGapDays = 1,

        [Parameter(Mandatory = $false)]
        [switch]$Create
    )

    $cacheDirectory = Get-DashboardCacheDirectory -BasePath $BasePath -ChildPath 'observed-windows' -Create:$Create
    return Join-Path $cacheDirectory ("gap{0}-{1}.json.gz" -f $AllowedGapDays, $Fingerprint)
}

function Clear-StaleVulnObservedWindowCache {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $false)]
        [string]$KeepPath
    )

    $cacheDirectory = Get-DashboardCacheDirectory -BasePath $BasePath -ChildPath 'observed-windows'
    if (-not (Test-Path -LiteralPath $cacheDirectory -PathType Container)) {
        return
    }

    $normalizedKeepPath = if ([string]::IsNullOrWhiteSpace($KeepPath)) {
        $null
    }
    else {
        [System.IO.Path]::GetFullPath($KeepPath)
    }

    foreach ($cacheFile in @(Get-ChildItem -Path $cacheDirectory -Filter '*.json.gz' -File -ErrorAction SilentlyContinue)) {
        if ($normalizedKeepPath -and ([System.StringComparer]::OrdinalIgnoreCase.Equals($cacheFile.FullName, $normalizedKeepPath))) {
            continue
        }

        Remove-Item -LiteralPath $cacheFile.FullName -Force -ErrorAction SilentlyContinue
    }
}

function Publish-VulnObservedWindowCache {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 30)]
        [int]$AllowedGapDays = 1
    )

    $fingerprint = Get-VulnObservedWindowCacheFingerprint -BasePath $BasePath -AllowedGapDays $AllowedGapDays
    if ([string]::IsNullOrWhiteSpace($fingerprint)) {
        return $null
    }

    $cachePath = Get-VulnObservedWindowCachePath -BasePath $BasePath -Fingerprint $fingerprint -AllowedGapDays $AllowedGapDays -Create
    if (Test-Path -LiteralPath $cachePath -PathType Leaf) {
        Clear-StaleVulnObservedWindowCache -BasePath $BasePath -KeepPath $cachePath
        return $cachePath
    }

    $tempPath = Join-Path (Split-Path -Parent $cachePath) ('.tmp-' + [System.Guid]::NewGuid().ToString('N') + '.json.gz')
    $fileStream = $null
    $gzipStream = $null
    $writer = $null
    try {
        Write-Information ("  Building observed-window cache from vulnerability store ({0})..." -f $fingerprint.Substring(0, 12)) -InformationAction Continue
        $fileStream = [System.IO.File]::Create($tempPath)
        $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Compress)
        $writer = [System.IO.StreamWriter]::new($gzipStream, [System.Text.UTF8Encoding]::new($false))

        foreach ($row in Write-MergedVulnObservedWindowRows -Source { Read-VulnStoreRow -BasePath $BasePath } -AllowedGapDays $AllowedGapDays) {
            if ($null -eq $row) { continue }
            $writer.WriteLine(($row | ConvertTo-Json -Compress -Depth 20))
        }
    }
    finally {
        if ($writer) { $writer.Dispose() }
        elseif ($gzipStream) { $gzipStream.Dispose() }
        elseif ($fileStream) { $fileStream.Dispose() }
    }

    if (Test-Path -LiteralPath $cachePath -PathType Leaf) {
        Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
    }
    else {
        Move-Item -LiteralPath $tempPath -Destination $cachePath -Force
    }

    Clear-StaleVulnObservedWindowCache -BasePath $BasePath -KeepPath $cachePath
    return $cachePath
}

function Get-MachineFingerprintSourceFileSet {
    [CmdletBinding()]
    [OutputType([System.IO.FileInfo[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    $files = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    $currentPath = Get-MachineCurrentPath -BasePath $BasePath
    $legacyCurrentPath = Get-LegacyCanonicalPath -Path $currentPath
    $currentReadPath = if (Test-Path -LiteralPath $currentPath -PathType Leaf) { $currentPath } elseif (Test-Path -LiteralPath $legacyCurrentPath -PathType Leaf) { $legacyCurrentPath } else { $null }

    if ($null -ne $currentReadPath) {
        $files.Add((Get-Item -LiteralPath $currentReadPath))
    }
    else {
        $historySourcePaths = @(Get-MachineHistorySourcePaths -BasePath $BasePath)
        if ($historySourcePaths.Count -gt 0) {
            foreach ($sourcePath in $historySourcePaths) {
                if (Test-Path -LiteralPath $sourcePath -PathType Leaf) {
                    $files.Add((Get-Item -LiteralPath $sourcePath))
                }
            }
        }
        else {
            foreach ($legacyMachineFile in @(Get-ChildItem -Path $BasePath -Filter 'Machines_*.json' -File -ErrorAction SilentlyContinue | Where-Object { Test-IsLegacyMachineSnapshotFileName -Name $_.Name } | Sort-Object Name -Descending)) {
                $files.Add($legacyMachineFile)
            }
        }
    }

    return [System.IO.FileInfo[]]$files.ToArray()
}

function Get-AdvancedHuntingFingerprintSourceFileSet {
    [CmdletBinding()]
    [OutputType([System.IO.FileInfo[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    $files = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    $currentPath = Get-AdvancedHuntingCurrentPath -BasePath $BasePath
    $legacyCurrentPath = Get-LegacyCanonicalPath -Path $currentPath

    if ((-not (Test-Path -LiteralPath $currentPath -PathType Leaf)) -and (Test-Path -LiteralPath $legacyCurrentPath -PathType Leaf)) {
        $currentPath = $legacyCurrentPath
    }

    if (Test-Path -LiteralPath $currentPath -PathType Leaf) {
        $files.Add((Get-Item -LiteralPath $currentPath))
    }
    else {
        foreach ($legacyAhFile in @(Get-ChildItem -Path $BasePath -Filter 'AdvancedHunting_*.json' -File -ErrorAction SilentlyContinue |
                Where-Object { Test-IsLegacyAdvancedHuntingSnapshotFileName -Name $_.Name } |
                Sort-Object Name -Descending)) {
            $files.Add($legacyAhFile)
        }
    }

    return [System.IO.FileInfo[]]$files.ToArray()
}

function Get-VulnerabilityPayloadFingerprintSourceFileSet {
    [CmdletBinding()]
    [OutputType([System.IO.FileInfo[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $false)]
        [switch]$SkipObservedWindowMerge
    )

    $syntheticManifestPath = Join-Path $BasePath 'synthetic-manifest.json'
    $effectiveSkipObservedWindowMerge = ($SkipObservedWindowMerge -or (Test-Path -LiteralPath $syntheticManifestPath -PathType Leaf))
    $files = [System.Collections.Generic.List[System.IO.FileInfo]]::new()

    $contentStoreExists = (Test-VulnContentStoreExistence -BasePath $BasePath)
    if ((Test-VulnStoreExistence -BasePath $BasePath) -or $contentStoreExists) {
        if ($effectiveSkipObservedWindowMerge) {
            if ($contentStoreExists) {
                foreach ($path in @(
                        (Get-VulnContentDictionaryPath -BasePath $BasePath)
                        (Get-VulnCurrentRefsPath -BasePath $BasePath)
                    )) {
                    if (Test-Path -LiteralPath $path -PathType Leaf) {
                        $files.Add((Get-Item -LiteralPath $path))
                    }
                }

                foreach ($historyRefsFile in @(Get-ChildItem -Path $BasePath -Filter 'VulnHistoryRefs_*.json.gz' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
                    $files.Add($historyRefsFile)
                }
            }
            else {
                $currentPath = Get-VulnCurrentPath -BasePath $BasePath
                if (Test-Path -LiteralPath $currentPath -PathType Leaf) {
                    $files.Add((Get-Item -LiteralPath $currentPath))
                }

                foreach ($historyRowsFile in @(Get-ChildItem -Path $BasePath -Filter 'VulnHistoryRows_*.json.gz' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
                    $files.Add($historyRowsFile)
                }
            }
        }
        else {
            $observedWindowCachePath = Publish-VulnObservedWindowCache -BasePath $BasePath
            if (-not [string]::IsNullOrWhiteSpace($observedWindowCachePath) -and (Test-Path -LiteralPath $observedWindowCachePath -PathType Leaf)) {
                $files.Add((Get-Item -LiteralPath $observedWindowCachePath))
            }
        }
    }
    else {
        foreach ($legacyFile in @(Get-VulnLegacySnapshotFile -BasePath $BasePath)) {
            if ($legacyFile -and (Test-Path -LiteralPath $legacyFile.FullName -PathType Leaf)) {
                $files.Add((Get-Item -LiteralPath $legacyFile.FullName))
            }
        }
    }

    return [System.IO.FileInfo[]]$files.ToArray()
}

function Get-DashboardPayloadCacheFingerprint {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $false)]
        [switch]$SkipObservedWindowMerge
    )

    $files = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    foreach ($file in @(Get-VulnerabilityPayloadFingerprintSourceFileSet -BasePath $BasePath -SkipObservedWindowMerge:$SkipObservedWindowMerge)) {
        if ($null -ne $file) { $files.Add($file) }
    }
    foreach ($file in @(Get-MachineFingerprintSourceFileSet -BasePath $BasePath)) {
        if ($null -ne $file) { $files.Add($file) }
    }
    foreach ($file in @(Get-AdvancedHuntingFingerprintSourceFileSet -BasePath $BasePath)) {
        if ($null -ne $file) { $files.Add($file) }
    }

    if ($files.Count -eq 0) {
        return $null
    }

    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.AppendLine('dashboard-payload-cache-v1')
    [void]$builder.AppendLine(('SkipObservedWindowMerge=' + ($SkipObservedWindowMerge -eq $true)))
    foreach ($file in @($files | Sort-Object FullName -Unique)) {
        $hash = Get-FileSha256Hex -Path $file.FullName
        [void]$builder.Append($file.FullName).Append('|')
        [void]$builder.Append($file.Length).Append('|')
        [void]$builder.Append($file.LastWriteTimeUtc.Ticks).Append('|')
        [void]$builder.AppendLine($hash)
    }

    $fingerprintBytes = [System.Text.Encoding]::UTF8.GetBytes($builder.ToString())
    $fingerprintHash = [System.Security.Cryptography.SHA256]::HashData($fingerprintBytes)
    return ([System.BitConverter]::ToString($fingerprintHash)).Replace('-', '').ToLowerInvariant()
}

function Get-NormalizedPayloadCachePath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $true)]
        [string]$Fingerprint,

        [Parameter(Mandatory = $false)]
        [switch]$Create
    )

    $cacheDirectory = Get-DashboardCacheDirectory -BasePath $BasePath -ChildPath 'payloads' -Create:$Create
    return Join-Path $cacheDirectory ("payload-{0}.json.gz" -f $Fingerprint)
}

function Get-NormalizedPayloadCacheManifestPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $true)]
        [string]$Fingerprint,

        [Parameter(Mandatory = $false)]
        [switch]$Create
    )

    $cacheDirectory = Get-DashboardCacheDirectory -BasePath $BasePath -ChildPath 'payloads' -Create:$Create
    return Join-Path $cacheDirectory ("payload-{0}.json" -f $Fingerprint)
}

function Clear-StaleNormalizedPayloadCache {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $false)]
        [string[]]$KeepPaths = @()
    )

    $cacheDirectory = Get-DashboardCacheDirectory -BasePath $BasePath -ChildPath 'payloads'
    if (-not (Test-Path -LiteralPath $cacheDirectory -PathType Container)) {
        return
    }

    $normalizedKeepPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($keepPath in @($KeepPaths)) {
        if (-not [string]::IsNullOrWhiteSpace($keepPath)) {
            [void]$normalizedKeepPaths.Add([System.IO.Path]::GetFullPath($keepPath))
        }
    }

    foreach ($cacheFile in @(Get-ChildItem -Path $cacheDirectory -File -ErrorAction SilentlyContinue)) {
        if ($normalizedKeepPaths.Contains($cacheFile.FullName)) {
            continue
        }

        Remove-Item -LiteralPath $cacheFile.FullName -Force -ErrorAction SilentlyContinue
    }
}

function Get-NormalizedPayloadCacheEntry {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $false)]
        [switch]$SkipObservedWindowMerge
    )

    $fingerprint = Get-DashboardPayloadCacheFingerprint -BasePath $BasePath -SkipObservedWindowMerge:$SkipObservedWindowMerge
    if ([string]::IsNullOrWhiteSpace($fingerprint)) {
        return $null
    }

    $payloadPath = Get-NormalizedPayloadCachePath -BasePath $BasePath -Fingerprint $fingerprint -Create
    $manifestPath = Get-NormalizedPayloadCacheManifestPath -BasePath $BasePath -Fingerprint $fingerprint -Create
    if ((-not (Test-Path -LiteralPath $payloadPath -PathType Leaf)) -or (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf))) {
        return $null
    }

    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -Depth 20
    if ([string]$manifest.Fingerprint -ne $fingerprint) {
        return $null
    }

    Clear-StaleNormalizedPayloadCache -BasePath $BasePath -KeepPaths @($payloadPath, $manifestPath)
    return [PSCustomObject]@{
        Fingerprint = $fingerprint
        PayloadPath = $payloadPath
        ManifestPath = $manifestPath
        Manifest = $manifest
    }
}

function Publish-NormalizedPayloadCache {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $true)]
        [string]$PayloadPath,

        [Parameter(Mandatory = $true)]
        [int]$VulnCount,

        [Parameter(Mandatory = $true)]
        [int]$DeviceCount,

        [Parameter(Mandatory = $true)]
        [int]$CveCount,

        [Parameter(Mandatory = $false)]
        [object]$Quality,

        [Parameter(Mandatory = $false)]
        [switch]$SkipObservedWindowMerge
    )

    $fingerprint = Get-DashboardPayloadCacheFingerprint -BasePath $BasePath -SkipObservedWindowMerge:$SkipObservedWindowMerge
    if ([string]::IsNullOrWhiteSpace($fingerprint)) {
        return $null
    }

    $cachePayloadPath = Get-NormalizedPayloadCachePath -BasePath $BasePath -Fingerprint $fingerprint -Create
    $cacheManifestPath = Get-NormalizedPayloadCacheManifestPath -BasePath $BasePath -Fingerprint $fingerprint -Create
    $tempPayloadPath = Join-Path (Split-Path -Parent $cachePayloadPath) ('.tmp-' + [System.Guid]::NewGuid().ToString('N') + '.json.gz')
    $tempManifestPath = Join-Path (Split-Path -Parent $cacheManifestPath) ('.tmp-' + [System.Guid]::NewGuid().ToString('N') + '.json')

    Copy-Item -LiteralPath $PayloadPath -Destination $tempPayloadPath -Force
    $manifest = [ordered]@{
        Version = 'dashboard-payload-cache-v1'
        Fingerprint = $fingerprint
        GeneratedOnUtc = (Get-Date).ToUniversalTime().ToString('o')
        VulnCount = $VulnCount
        DeviceCount = $DeviceCount
        CveCount = $CveCount
        Quality = $Quality
    }
    [System.IO.File]::WriteAllText($tempManifestPath, ($manifest | ConvertTo-Json -Compress -Depth 20), [System.Text.UTF8Encoding]::new($false))

    Move-Item -LiteralPath $tempPayloadPath -Destination $cachePayloadPath -Force
    Move-Item -LiteralPath $tempManifestPath -Destination $cacheManifestPath -Force
    Clear-StaleNormalizedPayloadCache -BasePath $BasePath -KeepPaths @($cachePayloadPath, $cacheManifestPath)

    return [PSCustomObject]@{
        Fingerprint = $fingerprint
        PayloadPath = $cachePayloadPath
        ManifestPath = $cacheManifestPath
        Manifest = [PSCustomObject]$manifest
    }
}

function Convert-CveUrl {
    [CmdletBinding()]
    [OutputType([string])]
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
        $cveId = $Matches[1]
        return "https://msrc.microsoft.com/update-guide/vulnerability/$cveId"
    }

    return $Url
}

function Get-GzipLine {
    param([string]$Path)
    $fs = [System.IO.File]::OpenRead($Path)
    $gs = [System.IO.Compression.GZipStream]::new($fs, [System.IO.Compression.CompressionMode]::Decompress)
    $lr = [System.IO.StreamReader]::new($gs, [System.Text.Encoding]::UTF8)
    try {
        while (-not $lr.EndOfStream) { $lr.ReadLine() }
    }
    finally { $lr.Dispose() }
}

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

function Get-CaseSensitiveIndexMap {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.Dictionary[string, int]])]
    param()

    return [System.Collections.Generic.Dictionary[string, int]]::new([System.StringComparer]::Ordinal)
}

function Get-NormalizationContext {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    return [PSCustomObject]@{
        Lookups = @{
            vendors = [System.Collections.Generic.List[string]]::new()
            severities = @('Critical', 'High', 'Medium', 'Low')
            exploitLevels = [System.Collections.Generic.List[string]]::new()
            groups = [System.Collections.Generic.List[string]]::new()
            platforms = [System.Collections.Generic.List[string]]::new()
            tags = [System.Collections.Generic.List[string]]::new()
            updates = [System.Collections.Generic.List[PSObject]]::new()
            versions = [System.Collections.Generic.List[string]]::new()
            dates = [System.Collections.Generic.List[string]]::new()
            diskPaths = [System.Collections.Generic.List[string]]::new()
            regPaths = [System.Collections.Generic.List[string]]::new()
            affSoftware = [System.Collections.Generic.List[string]]::new()
            batchTitles = [System.Collections.Generic.List[string]]::new()
            devices = [System.Collections.Generic.List[PSObject]]::new()
            software = [System.Collections.Generic.List[PSObject]]::new()
            cves = [System.Collections.Generic.List[PSObject]]::new()
        }
        Indexes = @{
            vendors = Get-CaseSensitiveIndexMap
            exploitLevels = Get-CaseSensitiveIndexMap
            groups = Get-CaseSensitiveIndexMap
            platforms = Get-CaseSensitiveIndexMap
            tags = Get-CaseSensitiveIndexMap
            updates = Get-CaseSensitiveIndexMap
            devices = Get-CaseSensitiveIndexMap
            software = Get-CaseSensitiveIndexMap
            cves = Get-CaseSensitiveIndexMap
            versions = Get-CaseSensitiveIndexMap
            dates = Get-CaseSensitiveIndexMap
            diskPaths = Get-CaseSensitiveIndexMap
            regPaths = Get-CaseSensitiveIndexMap
            affSoftware = Get-CaseSensitiveIndexMap
            batchTitles = Get-CaseSensitiveIndexMap
        }
        DateValueCache = @{}
    }
}

function Get-NormalizationCachedYmdDate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Context,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$DateValue
    )

    if ($null -eq $DateValue) {
        return $null
    }

    $cacheKey = $DateValue.ToString()
    if ($Context.DateValueCache.ContainsKey($cacheKey)) {
        return $Context.DateValueCache[$cacheKey]
    }

    $normalized = Convert-FastToYmdDate -DateValue $DateValue
    $Context.DateValueCache[$cacheKey] = $normalized
    return $normalized
}

function Convert-FastToYmdDate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$DateValue
    )

    if ($null -eq $DateValue) {
        return $null
    }

    $text = [string]$DateValue
    if ($text.Length -ge 10 -and $text[4] -eq '-' -and $text[7] -eq '-') {
        return $text.Substring(0, 10)
    }

    return Convert-ToYmdDate -DateValue $DateValue
}

function Convert-JsonElementToScalarValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Text.Json.JsonElement]$Element
    )

    switch ($Element.ValueKind) {
        ([System.Text.Json.JsonValueKind]::Undefined) { return $null }
        ([System.Text.Json.JsonValueKind]::Null) { return $null }
        ([System.Text.Json.JsonValueKind]::String) { return $Element.GetString() }
        ([System.Text.Json.JsonValueKind]::True) { return $true }
        ([System.Text.Json.JsonValueKind]::False) { return $false }
        ([System.Text.Json.JsonValueKind]::Number) {
            $int64Value = 0L
            if ($Element.TryGetInt64([ref]$int64Value)) {
                return $int64Value
            }

            $doubleValue = 0.0
            if ($Element.TryGetDouble([ref]$doubleValue)) {
                return $doubleValue
            }

            return $Element.GetRawText()
        }
        default { return $Element.GetRawText() }
    }
}

function Convert-JsonElementToStringArray {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Text.Json.JsonElement]$Element
    )

    if ($Element.ValueKind -ne [System.Text.Json.JsonValueKind]::Array) {
        return ,@()
    }

    $values = [System.Collections.Generic.List[string]]::new()
    foreach ($item in $Element.EnumerateArray()) {
        $value = Convert-JsonElementToScalarValue -Element $item
        if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value)) {
            $values.Add([string]$value)
        }
    }

    return ,([string[]]$values.ToArray())
}

function Get-JsonElementPropertyValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Text.Json.JsonElement]$Element,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [switch]$AsStringArray
    )

    $property = [System.Text.Json.JsonElement]::new()
    if (-not $Element.TryGetProperty($Name, [ref]$property)) {
        if ($AsStringArray) {
            return ,@()
        }

        return $null
    }

    if ($AsStringArray) {
        return Convert-JsonElementToStringArray -Element $property
    }

    return Convert-JsonElementToScalarValue -Element $property
}

function Invoke-ContentStoreNormalization {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DataPath,

        [Parameter(Mandatory = $true)]
        [string]$VulnOutputPath,

        [Parameter(Mandatory = $false)]
        [string]$VulnColumnDirectoryPath,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$Context,

        [Parameter(Mandatory = $true)]
        [hashtable]$Machines,

        [Parameter(Mandatory = $false)]
        [hashtable]$AdvancedHuntingData = @{}
    )

    $lookups = $Context.Lookups
    $vendorIndex = $Context.Indexes.vendors
    $exploitIndex = $Context.Indexes.exploitLevels
    $groupIndex = $Context.Indexes.groups
    $platformIndex = $Context.Indexes.platforms
    $tagIndex = $Context.Indexes.tags
    $updateIndex = $Context.Indexes.updates
    $deviceIndex = $Context.Indexes.devices
    $softwareIndex = $Context.Indexes.software
    $cveIndex = $Context.Indexes.cves
    $versionIndex = $Context.Indexes.versions
    $dateIndex = $Context.Indexes.dates
    $diskPathIndex = $Context.Indexes.diskPaths
    $regPathIndex = $Context.Indexes.regPaths
    $affSoftwareIndex = $Context.Indexes.affSoftware
    $batchTitleIndex = $Context.Indexes.batchTitles

    $dictionaryPath = Get-VulnContentDictionaryPath -BasePath $DataPath
    if (-not (Test-Path -LiteralPath $dictionaryPath -PathType Leaf)) {
        throw "Content dictionary '$dictionaryPath' was not found."
    }

    $dictionary = Read-VulnContentDictionary -Path $dictionaryPath
    $deviceProfiles = @($dictionary.deviceProfiles)
    $contentTemplates = @($dictionary.contentTemplates)
    $deviceProfileCount = $deviceProfiles.Count
    $contentTemplateCount = $contentTemplates.Count
    $deviceLookupIndices = New-Object 'System.Int32[]' $deviceProfileCount
    $deviceOnboardedFlags = New-Object 'System.Boolean[]' $deviceProfileCount
    $contentLookupCache = New-Object 'System.Object[]' $contentTemplateCount
    $processedCountRef = [ref]0
    $firstLastSwappedCountRef = [ref]0
    $hasNoTagsRef = [ref]$false
    $vulnWriter = $null
    $jsonWriter = $null
    $columnWriterSet = $null
    $vulnColumnPaths = $null

    for ($deviceProfileIndexValue = 0; $deviceProfileIndexValue -lt $deviceProfileCount; $deviceProfileIndexValue++) {
        $deviceProfile = $deviceProfiles[$deviceProfileIndexValue]
        $deviceId = [string]$deviceProfile.id
        $machine = if (-not [string]::IsNullOrWhiteSpace($deviceId)) { $Machines[$deviceId] } else { $null }
        $fallbackDeviceName = [string]$deviceProfile.n
        $fallbackGroupName = [string]$deviceProfile.g
        $fallbackPlatform = [string]$deviceProfile.o
        $fallbackOsVersion = [string]$deviceProfile.ov
        $deviceKey = if (-not [string]::IsNullOrWhiteSpace($deviceId)) {
            $deviceId
        }
        else {
            @(
                $fallbackDeviceName
                $fallbackGroupName
                $fallbackPlatform
                $fallbackOsVersion
            ) -join '|'
        }

        if (-not $deviceIndex.ContainsKey($deviceKey)) {
            $groupName = if ($machine) { $machine.PSObject.Properties['rbacGroupName']?.Value } else { $fallbackGroupName }
            if ([string]::IsNullOrWhiteSpace([string]$groupName)) {
                $groupName = if ([string]::IsNullOrWhiteSpace($fallbackGroupName)) { '(none)' } else { $fallbackGroupName }
            }
            $groupIdx = Get-OrCreateIndex -value $groupName -list $lookups.groups -indexMap $groupIndex

            $osPlat = if ($machine) { $machine.PSObject.Properties['osPlatform']?.Value } else { $fallbackPlatform }
            $platIdx = Get-OrCreateIndex -value $osPlat -list $lookups.platforms -indexMap $platformIndex

            $machineTags = if ($machine -and $machine.PSObject.Properties['machineTags']?.Value) { $machine.machineTags }
                          elseif ($deviceProfile.t) { @($deviceProfile.t) }
                          else { @() }
            $tagIndices = [System.Collections.Generic.List[int]]::new()
            foreach ($tag in $machineTags) {
                $tagIdx = Get-OrCreateIndex -value $tag -list $lookups.tags -indexMap $tagIndex
                if ($tagIdx -ge 0) { $tagIndices.Add($tagIdx) }
            }
            if ($tagIndices.Count -eq 0) { $hasNoTagsRef.Value = $true }

            $deviceIndex[$deviceKey] = $lookups.devices.Count

            $machineInfo = $null
            if ($machine) {
                $machineLastSeen = $machine.PSObject.Properties['lastSeen']?.Value
                $machineFirstSeen = $machine.PSObject.Properties['firstSeen']?.Value
                $machineInfo = [PSCustomObject]@{
                    ip = $machine.PSObject.Properties['lastIpAddress']?.Value
                    eip = $machine.PSObject.Properties['lastExternalIpAddress']?.Value
                    hs = $machine.PSObject.Properties['healthStatus']?.Value
                    rs = $machine.PSObject.Properties['riskScore']?.Value
                    el = $machine.PSObject.Properties['exposureLevel']?.Value
                    dv = $machine.PSObject.Properties['deviceValue']?.Value
                    mb = $machine.PSObject.Properties['managedBy']?.Value
                    aad = $machine.PSObject.Properties['isAadJoined']?.Value
                    ls = Get-NormalizationCachedYmdDate -Context $Context -DateValue $machineLastSeen
                    fs = Get-NormalizationCachedYmdDate -Context $Context -DateValue $machineFirstSeen
                }
            }

            $lookups.devices.Add([PSCustomObject]@{
                id = $deviceId
                n = if ($machine) { $machine.PSObject.Properties['computerDnsName']?.Value } elseif ($fallbackDeviceName) { $fallbackDeviceName } else { '(no machine data)' }
                g = $groupIdx
                o = $platIdx
                ov = if ($machine) { $machine.PSObject.Properties['osVersion']?.Value } else { $fallbackOsVersion }
                t = $tagIndices
                m = $machineInfo
            })
        }

        $deviceLookupIndices[$deviceProfileIndexValue] = [int]$deviceIndex[$deviceKey]
        $deviceOnboardedFlags[$deviceProfileIndexValue] = ($deviceProfile.ob -eq $true)
    }

    for ($contentTemplateIndexValue = 0; $contentTemplateIndexValue -lt $contentTemplateCount; $contentTemplateIndexValue++) {
        $contentTemplate = $contentTemplates[$contentTemplateIndexValue]
        $softwareVendor = [string]$contentTemplate.sv
        $vendorIdx = Get-OrCreateIndex -value $softwareVendor -list $lookups.vendors -indexMap $vendorIndex

        $softwareName = [string]$contentTemplate.sn
        $recommendationReference = [string]$contentTemplate.rr
        $softwareKey = "$softwareVendor|$softwareName|$recommendationReference"
        if (-not $softwareIndex.ContainsKey($softwareKey)) {
            $softwareIndex[$softwareKey] = $lookups.software.Count
            $lookups.software.Add([PSCustomObject]@{
                v = $vendorIdx
                n = $softwareName
                r = $recommendationReference
            })
        }
        $swIdx = [int]$softwareIndex[$softwareKey]

        $cveId = [string]$contentTemplate.c
        $cvssScore = $contentTemplate.sc
        $sevLevel = [string]$contentTemplate.sev
        $sevIdx = switch ($sevLevel) {
            'Critical' { 0 }
            'High' { 1 }
            'Medium' { 2 }
            'Low' { 3 }
            default { -1 }
        }

        $exploitabilityLevel = [string]$contentTemplate.ex
        $expIdx = Get-OrCreateIndex -value $exploitabilityLevel -list $lookups.exploitLevels -indexMap $exploitIndex
        $cveBatchUrl = Convert-CveUrl -Url ([string]$contentTemplate.bu)
        $btValue = [string]$contentTemplate.bt
        $cveKey = @(
            $cveId
            [string]$cvssScore
            $sevLevel
            $exploitabilityLevel
            [string]$cveBatchUrl
            $btValue
        ) -join '|'

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
                id = $cveId
                sc = $cvssScore
                sv = $sevIdx
                ex = $expIdx
                u = $cveBatchUrl
                bt = $btIdx
                pd = $publishedDate
                desc = $vulnDescription
                ep = $epssScore
                as = $affSoftwareIndices
            })
        }
        $cveIdx = [int]$cveIndex[$cveKey]

        $recUpdate = [string]$contentTemplate.ru
        $recUpdateId = [string]$contentTemplate.rid
        $recUpdateUrl = [string]$contentTemplate.url
        $updateName = if ($recUpdate -and $recUpdate -ne '--') { $recUpdate } else { $null }
        if ($null -eq $updateName -or $updateName -eq '') {
            $updIdx = -1
        }
        else {
            $updateKey = @(
                $updateName
                $recUpdateId
                $recUpdateUrl
            ) -join '|'
            if ($updateIndex.ContainsKey($updateKey)) {
                $updIdx = [int]$updateIndex[$updateKey]
            }
            else {
                $updIdx = $lookups.updates.Count
                $updateIndex[$updateKey] = $updIdx
                $lookups.updates.Add([PSCustomObject]@{
                    n = $updateName
                    id = $recUpdateId
                    url = $recUpdateUrl
                })
            }
        }

        $versionIdx = Get-OrCreateIndex -value ([string]$contentTemplate.ver) -list $lookups.versions -indexMap $versionIndex
        $diskPathIndices = $null
        $regPathIndices = $null
        if ($contentTemplate.dp -and @($contentTemplate.dp).Count -gt 0) {
            $diskPathIndices = [System.Collections.Generic.List[int]]::new()
            foreach ($dp in @($contentTemplate.dp)) {
                $dpIdx = Get-OrCreateIndex -value $dp -list $lookups.diskPaths -indexMap $diskPathIndex
                if ($dpIdx -ge 0) { $diskPathIndices.Add($dpIdx) }
            }
        }
        if ($contentTemplate.rp -and @($contentTemplate.rp).Count -gt 0) {
            $regPathIndices = [System.Collections.Generic.List[int]]::new()
            foreach ($rp in @($contentTemplate.rp)) {
                $rpIdx = Get-OrCreateIndex -value $rp -list $lookups.regPaths -indexMap $regPathIndex
                if ($rpIdx -ge 0) { $regPathIndices.Add($rpIdx) }
            }
        }

        $contentLookupCache[$contentTemplateIndexValue] = [PSCustomObject]@{
            sw = $swIdx
            cve = $cveIdx
            ver = $versionIdx
            upd = $updIdx
            ua = [int]($contentTemplate.ua -eq $true)
            dp = $diskPathIndices
            rp = $regPathIndices
        }
    }

    try {
        if (-not [string]::IsNullOrWhiteSpace($VulnColumnDirectoryPath)) {
            $columnWriterSet = Open-CompactVulnColumnWriterSet -DirectoryPath $VulnColumnDirectoryPath
            $vulnColumnPaths = $columnWriterSet.Paths
        }
        else {
            $vulnWriter = [System.IO.StreamWriter]::new($VulnOutputPath, $false, [System.Text.UTF8Encoding]::new($false))
            $jsonWriter = [Newtonsoft.Json.JsonTextWriter]::new($vulnWriter)
            $jsonWriter.Formatting = [Newtonsoft.Json.Formatting]::None
            $jsonWriter.WriteStartArray()
        }

        $refPaths = [System.Collections.Generic.List[pscustomobject]]::new()
        $currentRefsPath = Get-VulnCurrentRefsPath -BasePath $DataPath
        if (Test-Path -LiteralPath $currentRefsPath -PathType Leaf) {
            $refPaths.Add([PSCustomObject]@{
                Path = $currentRefsPath
                Label = (Split-Path -Leaf $currentRefsPath)
            })
        }

        foreach ($historyRefsFile in @(Get-ChildItem -Path $DataPath -Filter 'VulnHistoryRefs_*.json.gz' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
            $refPaths.Add([PSCustomObject]@{
                Path = $historyRefsFile.FullName
                Label = $historyRefsFile.Name
            })
        }

        foreach ($refPath in $refPaths) {
            Invoke-VulnNdjsonLineAction -Path ([string]$refPath.Path) -Action {
                param([string]$JsonLine)

                $document = [System.Text.Json.JsonDocument]::Parse($JsonLine)
                try {
                    $root = $document.RootElement
                    $elements = $root.EnumerateArray()
                    [void]$elements.MoveNext()
                    [void]$elements.MoveNext()
                    $deviceProfileIndexValue = $elements.Current.GetInt32()
                    [void]$elements.MoveNext()
                    $contentTemplateIndexValue = $elements.Current.GetInt32()
                    [void]$elements.MoveNext()
                    $firstSeenValue = if ($elements.Current.ValueKind -eq [System.Text.Json.JsonValueKind]::Null) { $null } else { $elements.Current.GetString() }
                    [void]$elements.MoveNext()
                    $lastSeenValue = if ($elements.Current.ValueKind -eq [System.Text.Json.JsonValueKind]::Null) { $null } else { $elements.Current.GetString() }

                    if (($deviceProfileIndexValue -lt 0) -or ($deviceProfileIndexValue -ge $deviceProfileCount)) { return }
                    if (($contentTemplateIndexValue -lt 0) -or ($contentTemplateIndexValue -ge $contentTemplateCount)) { return }
                    if (-not $deviceOnboardedFlags[$deviceProfileIndexValue]) { return }

                    $processedCountRef.Value++

                    $seenWindow = Get-NormalizedVulnSeenWindow -FirstSeenValue $firstSeenValue -LastSeenValue $lastSeenValue
                    $firstSeen = if ($seenWindow.FirstSeenTimestamp) { Get-NormalizationCachedYmdDate -Context $Context -DateValue $seenWindow.FirstSeenTimestamp } else { $null }
                    $lastSeen = if ($seenWindow.LastSeenTimestamp) { Get-NormalizationCachedYmdDate -Context $Context -DateValue $seenWindow.LastSeenTimestamp } else { $null }
                    if ($seenWindow.WasReordered) {
                        $firstLastSwappedCountRef.Value++
                    }

                    if (-not $firstSeen) { $firstSeen = '' }
                    if (-not $lastSeen) { $lastSeen = '' }
                    $firstSeenIdx = Get-OrCreateIndex -value $firstSeen -list $lookups.dates -indexMap $dateIndex
                    $lastSeenIdx = Get-OrCreateIndex -value $lastSeen -list $lookups.dates -indexMap $dateIndex

                    $contentLookup = $contentLookupCache[$contentTemplateIndexValue]
                    $compactRecord = New-Object object[] 10
                    $compactRecord[0] = $deviceLookupIndices[$deviceProfileIndexValue]
                    $compactRecord[1] = $contentLookup.cve
                    $compactRecord[2] = $contentLookup.sw
                    $compactRecord[3] = $contentLookup.ver
                    $compactRecord[4] = $firstSeenIdx
                    $compactRecord[5] = $lastSeenIdx
                    $compactRecord[6] = $contentLookup.ua
                    $compactRecord[7] = $contentLookup.upd
                    $compactRecord[8] = $contentLookup.dp
                    $compactRecord[9] = $contentLookup.rp

                    if ($columnWriterSet) {
                        Write-CompactVulnRecordColumnSet -WriterSet $columnWriterSet -Record $compactRecord
                    }
                    else {
                        $jsonWriter.WriteStartArray()
                        foreach ($compactValue in $compactRecord) {
                            if ($null -eq $compactValue) {
                                $jsonWriter.WriteNull()
                                continue
                            }

                            if ($compactValue -is [System.Collections.IEnumerable] -and $compactValue -isnot [string]) {
                                $jsonWriter.WriteStartArray()
                                foreach ($nestedValue in $compactValue) {
                                    if ($null -eq $nestedValue) {
                                        $jsonWriter.WriteNull()
                                    }
                                    else {
                                        $jsonWriter.WriteValue($nestedValue)
                                    }
                                }
                                $jsonWriter.WriteEndArray()
                                continue
                            }

                            $jsonWriter.WriteValue($compactValue)
                        }
                        $jsonWriter.WriteEndArray()
                    }

                    if (($processedCountRef.Value % 50000) -eq 0) {
                        Write-Information ("  Processed {0} onboarded vulnerability record(s)..." -f $processedCountRef.Value) -InformationAction Continue
                    }

                    if (($processedCountRef.Value % 100000) -eq 0) {
                        if ($columnWriterSet) {
                            Sync-CompactVulnColumnWriterSet -WriterSet $columnWriterSet
                        }
                        else {
                            $jsonWriter.Flush()
                        }
                        Invoke-FullGarbageCollection
                    }
                }
                finally {
                    $document.Dispose()
                }
            }
        }

        if ($columnWriterSet) {
            Sync-CompactVulnColumnWriterSet -WriterSet $columnWriterSet
        }
        else {
            $jsonWriter.WriteEndArray()
            $jsonWriter.Flush()
        }
    }
    finally {
        if ($jsonWriter) {
            $jsonWriter.Close()
        }
        if ($vulnWriter) {
            $vulnWriter.Dispose()
        }
        if ($columnWriterSet) {
            Close-CompactVulnColumnWriterSet -WriterSet $columnWriterSet
        }
    }

    return [PSCustomObject]@{
        ProcessedCount = $processedCountRef.Value
        FirstLastSwappedCount = $firstLastSwappedCountRef.Value
        HasNoTags = ($hasNoTagsRef.Value -eq $true)
        VulnsPath = if ($columnWriterSet) { $null } else { $VulnOutputPath }
        VulnColumnPaths = $vulnColumnPaths
    }
}

function Invoke-RawStoreNormalization {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DataPath,

        [Parameter(Mandatory = $true)]
        [string]$VulnOutputPath,

        [Parameter(Mandatory = $false)]
        [string]$VulnColumnDirectoryPath,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$Context,

        [Parameter(Mandatory = $true)]
        [hashtable]$Machines,

        [Parameter(Mandatory = $false)]
        [hashtable]$AdvancedHuntingData = @{}
    )

    $normalizationMachines = $Machines
    $normalizationAdvancedHuntingData = $AdvancedHuntingData
    $lookups = $Context.Lookups
    $vendorIndex = $Context.Indexes.vendors
    $exploitIndex = $Context.Indexes.exploitLevels
    $groupIndex = $Context.Indexes.groups
    $platformIndex = $Context.Indexes.platforms
    $tagIndex = $Context.Indexes.tags
    $updateIndex = $Context.Indexes.updates
    $deviceIndex = $Context.Indexes.devices
    $softwareIndex = $Context.Indexes.software
    $cveIndex = $Context.Indexes.cves
    $versionIndex = $Context.Indexes.versions
    $dateIndex = $Context.Indexes.dates
    $diskPathIndex = $Context.Indexes.diskPaths
    $regPathIndex = $Context.Indexes.regPaths
    $affSoftwareIndex = $Context.Indexes.affSoftware
    $batchTitleIndex = $Context.Indexes.batchTitles

    $processedCountRef = [ref]0
    $firstLastSwappedCountRef = [ref]0
    $hasNoTagsRef = [ref]$false
    $vulnWriter = $null
    $jsonWriter = $null
    $columnWriterSet = $null
    $vulnColumnPaths = $null

    try {
        if (-not [string]::IsNullOrWhiteSpace($VulnColumnDirectoryPath)) {
            $columnWriterSet = Open-CompactVulnColumnWriterSet -DirectoryPath $VulnColumnDirectoryPath
            $vulnColumnPaths = $columnWriterSet.Paths
        }
        else {
            $vulnWriter = [System.IO.StreamWriter]::new($VulnOutputPath, $false, [System.Text.UTF8Encoding]::new($false))
            $jsonWriter = [Newtonsoft.Json.JsonTextWriter]::new($vulnWriter)
            $jsonWriter.Formatting = [Newtonsoft.Json.Formatting]::None
            $jsonWriter.WriteStartArray()
        }

        Invoke-WithStoreLock -BasePath $DataPath -StoreName 'vuln' -ScriptBlock {
            Restore-StoreTransaction -BasePath $DataPath -StoreName 'vuln'

            $storePaths = [System.Collections.Generic.List[pscustomobject]]::new()
            $currentPath = Get-VulnCurrentPath -BasePath $DataPath
            if (Test-Path -LiteralPath $currentPath -PathType Leaf) {
                $storePaths.Add([PSCustomObject]@{
                    Path = $currentPath
                    Label = (Split-Path -Leaf $currentPath)
                })
            }

            foreach ($historyRowsFile in @(Get-ChildItem -Path $DataPath -Filter 'VulnHistoryRows_*.json.gz' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
                $storePaths.Add([PSCustomObject]@{
                    Path = $historyRowsFile.FullName
                    Label = $historyRowsFile.Name
                })
            }

            foreach ($storePath in $storePaths) {
                if (Get-Command -Name Write-MemoryUsage -ErrorAction SilentlyContinue) {
                    Write-MemoryUsage -Label ("VulnStore " + $storePath.Label + " Start")
                }

                Invoke-VulnNdjsonJsonRootAction -Path ([string]$storePath.Path) -Action {
                    param([System.Text.Json.JsonElement]$root)

                        $isOnboarded = Get-JsonElementPropertyValue -Element $root -Name 'IsOnboarded'
                        if ($isOnboarded -ne $true) { return }

                        $processedCountRef.Value++

                        $deviceId = [string](Get-JsonElementPropertyValue -Element $root -Name 'DeviceId')
                        $machine = $normalizationMachines[$deviceId]
                        $fallbackDeviceName = Get-JsonElementPropertyValue -Element $root -Name 'DeviceName'
                        $fallbackGroupName = Get-JsonElementPropertyValue -Element $root -Name 'RbacGroupName'
                        $fallbackPlatform = Get-JsonElementPropertyValue -Element $root -Name 'OSPlatform'
                        $fallbackOsVersion = Get-JsonElementPropertyValue -Element $root -Name 'OSVersion'
                        $deviceKey = if (-not [string]::IsNullOrWhiteSpace($deviceId)) {
                            $deviceId
                        }
                        else {
                            @(
                                [string]$fallbackDeviceName
                                [string]$fallbackGroupName
                                [string]$fallbackPlatform
                                [string]$fallbackOsVersion
                            ) -join '|'
                        }

                        if (-not $deviceIndex.ContainsKey($deviceKey)) {
                            $groupName = if ($machine) { $machine.PSObject.Properties['rbacGroupName']?.Value } else { $fallbackGroupName }
                            if ([string]::IsNullOrWhiteSpace([string]$groupName)) {
                                $groupName = if ([string]::IsNullOrWhiteSpace([string]$fallbackGroupName)) { '(none)' } else { $fallbackGroupName }
                            }
                            $groupIdx = Get-OrCreateIndex -value $groupName -list $lookups.groups -indexMap $groupIndex

                            $osPlat = if ($machine) { $machine.PSObject.Properties['osPlatform']?.Value } else { $fallbackPlatform }
                            $platIdx = Get-OrCreateIndex -value $osPlat -list $lookups.platforms -indexMap $platformIndex

                            $rowMachineTags = Get-JsonElementPropertyValue -Element $root -Name 'MachineTags' -AsStringArray
                            $machineTags = if ($machine -and $machine.PSObject.Properties['machineTags']?.Value) { $machine.machineTags }
                                          elseif ($rowMachineTags) { $rowMachineTags }
                                          else { @() }
                            $tagIndices = [System.Collections.Generic.List[int]]::new()
                            foreach ($tag in $machineTags) {
                                $tagIdx = Get-OrCreateIndex -value $tag -list $lookups.tags -indexMap $tagIndex
                                if ($tagIdx -ge 0) { $tagIndices.Add($tagIdx) }
                            }
                            if ($tagIndices.Count -eq 0) { $hasNoTagsRef.Value = $true }

                            $deviceIndex[$deviceKey] = $lookups.devices.Count

                            $machineInfo = $null
                            if ($machine) {
                                $machineLastSeen = $machine.PSObject.Properties['lastSeen']?.Value
                                $machineFirstSeen = $machine.PSObject.Properties['firstSeen']?.Value
                                $machineInfo = [PSCustomObject]@{
                                    ip = $machine.PSObject.Properties['lastIpAddress']?.Value
                                    eip = $machine.PSObject.Properties['lastExternalIpAddress']?.Value
                                    hs = $machine.PSObject.Properties['healthStatus']?.Value
                                    rs = $machine.PSObject.Properties['riskScore']?.Value
                                    el = $machine.PSObject.Properties['exposureLevel']?.Value
                                    dv = $machine.PSObject.Properties['deviceValue']?.Value
                                    mb = $machine.PSObject.Properties['managedBy']?.Value
                                    aad = $machine.PSObject.Properties['isAadJoined']?.Value
                                    ls = Get-NormalizationCachedYmdDate -Context $Context -DateValue $machineLastSeen
                                    fs = Get-NormalizationCachedYmdDate -Context $Context -DateValue $machineFirstSeen
                                }
                            }

                            $lookups.devices.Add([PSCustomObject]@{
                                id = $deviceId
                                n = if ($machine) { $machine.PSObject.Properties['computerDnsName']?.Value } elseif ($fallbackDeviceName) { $fallbackDeviceName } else { '(no machine data)' }
                                g = $groupIdx
                                o = $platIdx
                                ov = if ($machine) { $machine.PSObject.Properties['osVersion']?.Value } else { $fallbackOsVersion }
                                t = $tagIndices
                                m = $machineInfo
                            })
                        }
                        $devIdx = $deviceIndex[$deviceKey]

                        $softwareVendor = (Get-JsonElementPropertyValue -Element $root -Name 'SoftwareVendor') ?? ''
                        $vendorIdx = Get-OrCreateIndex -value $softwareVendor -list $lookups.vendors -indexMap $vendorIndex

                        $softwareName = (Get-JsonElementPropertyValue -Element $root -Name 'SoftwareName') ?? ''
                        $recommendationReference = (Get-JsonElementPropertyValue -Element $root -Name 'RecommendationReference') ?? ''
                        $softwareKey = "$softwareVendor|$softwareName|$recommendationReference"
                        if (-not $softwareIndex.ContainsKey($softwareKey)) {
                            $softwareIndex[$softwareKey] = $lookups.software.Count
                            $lookups.software.Add([PSCustomObject]@{
                                v = $vendorIdx
                                n = $softwareName
                                r = $recommendationReference
                            })
                        }
                        $swIdx = $softwareIndex[$softwareKey]

                        $cveId = Get-JsonElementPropertyValue -Element $root -Name 'CveId'
                        $cvssScore = Get-JsonElementPropertyValue -Element $root -Name 'CvssScore'
                        $sevLevel = Get-JsonElementPropertyValue -Element $root -Name 'VulnerabilitySeverityLevel'
                        $sevIdx = switch ($sevLevel) {
                            'Critical' { 0 }
                            'High' { 1 }
                            'Medium' { 2 }
                            'Low' { 3 }
                            default { -1 }
                        }

                        $exploitabilityLevel = Get-JsonElementPropertyValue -Element $root -Name 'ExploitabilityLevel'
                        $expIdx = Get-OrCreateIndex -value $exploitabilityLevel -list $lookups.exploitLevels -indexMap $exploitIndex

                        $cveBatchUrl = Convert-CveUrl -Url (Get-JsonElementPropertyValue -Element $root -Name 'CveBatchUrl')
                        $btValue = Get-JsonElementPropertyValue -Element $root -Name 'CveBatchTitle'
                        $cveKey = @(
                            [string]$cveId,
                            [string]$cvssScore,
                            [string]$sevLevel,
                            [string]$exploitabilityLevel,
                            [string]$cveBatchUrl,
                            [string]$btValue
                        ) -join '|'

                        if (-not $cveIndex.ContainsKey($cveKey)) {
                            $ahData = $normalizationAdvancedHuntingData[[string]$cveId]
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
                                id = $cveId
                                sc = $cvssScore
                                sv = $sevIdx
                                ex = $expIdx
                                u = $cveBatchUrl
                                bt = $btIdx
                                pd = $publishedDate
                                desc = $vulnDescription
                                ep = $epssScore
                                as = $affSoftwareIndices
                            })
                        }
                        $cveIdx = $cveIndex[$cveKey]

                        $recUpdate = Get-JsonElementPropertyValue -Element $root -Name 'RecommendedSecurityUpdate'
                        $recUpdateId = Get-JsonElementPropertyValue -Element $root -Name 'RecommendedSecurityUpdateId'
                        $recUpdateUrl = Get-JsonElementPropertyValue -Element $root -Name 'RecommendedSecurityUpdateUrl'
                        $updateName = if ($recUpdate -and $recUpdate -ne '--') { $recUpdate } else { $null }
                        if ($null -eq $updateName -or $updateName -eq '') {
                            $updIdx = -1
                        }
                        else {
                            $updateKey = @(
                                [string]$updateName,
                                [string]$recUpdateId,
                                [string]$recUpdateUrl
                            ) -join '|'
                            if ($updateIndex.ContainsKey($updateKey)) {
                                $updIdx = $updateIndex[$updateKey]
                            }
                            else {
                                $updIdx = $lookups.updates.Count
                                $updateIndex[$updateKey] = $updIdx
                                $lookups.updates.Add([PSCustomObject]@{
                                    n = $updateName
                                    id = $recUpdateId
                                    url = $recUpdateUrl
                                })
                            }
                        }

                        $seenWindow = Get-NormalizedVulnSeenWindow `
                            -FirstSeenValue (Get-JsonElementPropertyValue -Element $root -Name 'FirstSeenTimestamp') `
                            -LastSeenValue (Get-JsonElementPropertyValue -Element $root -Name 'LastSeenTimestamp')
                        $firstSeen = if ($seenWindow.FirstSeenTimestamp) { Get-NormalizationCachedYmdDate -Context $Context -DateValue $seenWindow.FirstSeenTimestamp } else { $null }
                        $lastSeen = if ($seenWindow.LastSeenTimestamp) { Get-NormalizationCachedYmdDate -Context $Context -DateValue $seenWindow.LastSeenTimestamp } else { $null }
                        if ($seenWindow.WasReordered) {
                            $firstLastSwappedCountRef.Value++
                        }

                        if (-not $firstSeen) { $firstSeen = '' }
                        if (-not $lastSeen) { $lastSeen = '' }
                        $firstSeenIdx = Get-OrCreateIndex -value $firstSeen -list $lookups.dates -indexMap $dateIndex
                        $lastSeenIdx = Get-OrCreateIndex -value $lastSeen -list $lookups.dates -indexMap $dateIndex

                        $versionStr = Get-JsonElementPropertyValue -Element $root -Name 'SoftwareVersion'
                        $versionIdx = Get-OrCreateIndex -value $versionStr -list $lookups.versions -indexMap $versionIndex

                        $rawDiskPaths = Get-JsonElementPropertyValue -Element $root -Name 'DiskPaths' -AsStringArray
                        $rawRegPaths = Get-JsonElementPropertyValue -Element $root -Name 'RegistryPaths' -AsStringArray
                        $diskPathIndices = $null
                        $regPathIndices = $null
                        if ($rawDiskPaths -and @($rawDiskPaths).Count -gt 0) {
                            $diskPathIndices = [System.Collections.Generic.List[int]]::new()
                            foreach ($dp in $rawDiskPaths) {
                                $dpIdx = Get-OrCreateIndex -value $dp -list $lookups.diskPaths -indexMap $diskPathIndex
                                if ($dpIdx -ge 0) { $diskPathIndices.Add($dpIdx) }
                            }
                        }
                        if ($rawRegPaths -and @($rawRegPaths).Count -gt 0) {
                            $regPathIndices = [System.Collections.Generic.List[int]]::new()
                            foreach ($rp in $rawRegPaths) {
                                $rpIdx = Get-OrCreateIndex -value $rp -list $lookups.regPaths -indexMap $regPathIndex
                                if ($rpIdx -ge 0) { $regPathIndices.Add($rpIdx) }
                            }
                        }

                        $secUpdateAvail = Get-JsonElementPropertyValue -Element $root -Name 'SecurityUpdateAvailable'
                        $compactRecord = New-Object object[] 10
                        $compactRecord[0] = $devIdx
                        $compactRecord[1] = $cveIdx
                        $compactRecord[2] = $swIdx
                        $compactRecord[3] = $versionIdx
                        $compactRecord[4] = $firstSeenIdx
                        $compactRecord[5] = $lastSeenIdx
                        $compactRecord[6] = [int]($secUpdateAvail -eq $true)
                        $compactRecord[7] = $updIdx
                        $compactRecord[8] = $diskPathIndices
                        $compactRecord[9] = $regPathIndices

                        if ($columnWriterSet) {
                            Write-CompactVulnRecordColumnSet -WriterSet $columnWriterSet -Record $compactRecord
                        }
                        else {
                            $jsonWriter.WriteStartArray()
                            foreach ($compactValue in $compactRecord) {
                                if ($null -eq $compactValue) {
                                    $jsonWriter.WriteNull()
                                    continue
                                }

                                if ($compactValue -is [System.Collections.IEnumerable] -and $compactValue -isnot [string]) {
                                    $jsonWriter.WriteStartArray()
                                    foreach ($nestedValue in $compactValue) {
                                        if ($null -eq $nestedValue) {
                                            $jsonWriter.WriteNull()
                                        }
                                        else {
                                            $jsonWriter.WriteValue($nestedValue)
                                        }
                                    }
                                    $jsonWriter.WriteEndArray()
                                    continue
                                }

                                $jsonWriter.WriteValue($compactValue)
                            }
                            $jsonWriter.WriteEndArray()
                        }

                        if (($processedCountRef.Value % 50000) -eq 0) {
                            Write-Information ("  Processed {0} onboarded vulnerability record(s)..." -f $processedCountRef.Value) -InformationAction Continue
                        }

                        if (($processedCountRef.Value % 100000) -eq 0) {
                            if ($columnWriterSet) {
                                Sync-CompactVulnColumnWriterSet -WriterSet $columnWriterSet
                            }
                            else {
                                $jsonWriter.Flush()
                            }
                            Invoke-FullGarbageCollection
                        }
                }

                if (Get-Command -Name Write-MemoryUsage -ErrorAction SilentlyContinue) {
                    Write-MemoryUsage -Label ("VulnStore " + $storePath.Label + " End")
                }
            }
        } | Out-Null

        if ($columnWriterSet) {
            Sync-CompactVulnColumnWriterSet -WriterSet $columnWriterSet
        }
        else {
            $jsonWriter.WriteEndArray()
            $jsonWriter.Flush()
        }
    }
    finally {
        if ($jsonWriter) {
            $jsonWriter.Close()
        }
        if ($vulnWriter) {
            $vulnWriter.Dispose()
        }
        if ($columnWriterSet) {
            Close-CompactVulnColumnWriterSet -WriterSet $columnWriterSet
        }
    }

    return [PSCustomObject]@{
        ProcessedCount = $processedCountRef.Value
        FirstLastSwappedCount = $firstLastSwappedCountRef.Value
        HasNoTags = ($hasNoTagsRef.Value -eq $true)
        VulnsPath = if ($columnWriterSet) { $null } else { $VulnOutputPath }
        VulnColumnPaths = $vulnColumnPaths
    }
}

function Get-VulnObservedWindowIdentityKey {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        $Row
    )

    $id = [string](Get-VulnPropertyValue -InputObject $Row -Name 'Id')
    if (-not [string]::IsNullOrWhiteSpace($id)) {
        return $id
    }

    $sourceId = [string](Get-VulnPropertyValue -InputObject $Row -Name 'SourceId')
    if (-not [string]::IsNullOrWhiteSpace($sourceId)) {
        return $sourceId
    }

    return @(
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'DeviceId')
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'CveId')
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'SoftwareVendor')
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'SoftwareName')
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'SoftwareVersion')
    ) -join '|'
}

function Merge-VulnObservedWindowRows {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Rows,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 30)]
        [int]$AllowedGapDays = 1
    )

    if (@($Rows).Count -le 1) {
        return @($Rows)
    }

    $rowsByIdentity = @{}
    foreach ($row in @($Rows)) {
        if ($null -eq $row) { continue }

        $identityKey = Get-VulnObservedWindowIdentityKey -Row $row
        if (-not $rowsByIdentity.ContainsKey($identityKey)) {
            $rowsByIdentity[$identityKey] = [System.Collections.Generic.List[object]]::new()
        }
        $rowsByIdentity[$identityKey].Add($row)
    }

    $mergedRows = [System.Collections.Generic.List[object]]::new()
    foreach ($identityKey in @($rowsByIdentity.Keys | Sort-Object)) {
        $items = @($rowsByIdentity[$identityKey] | Sort-Object FirstSeenTimestamp, LastSeenTimestamp)
        if ($items.Count -eq 0) { continue }

        $current = Copy-VulnRecord -Record $items[0]
        for ($index = 1; $index -lt $items.Count; $index++) {
            $candidate = $items[$index]
            $currentWindow = Get-NormalizedVulnSeenWindow `
                -FirstSeenValue (Get-VulnPropertyValue -InputObject $current -Name 'FirstSeenTimestamp') `
                -LastSeenValue (Get-VulnPropertyValue -InputObject $current -Name 'LastSeenTimestamp')
            $candidateWindow = Get-NormalizedVulnSeenWindow `
                -FirstSeenValue (Get-VulnPropertyValue -InputObject $candidate -Name 'FirstSeenTimestamp') `
                -LastSeenValue (Get-VulnPropertyValue -InputObject $candidate -Name 'LastSeenTimestamp')

            $shouldMerge = $false
            if (
                -not [string]::IsNullOrWhiteSpace($currentWindow.FirstSeenTimestamp) -and
                -not [string]::IsNullOrWhiteSpace($currentWindow.LastSeenTimestamp) -and
                -not [string]::IsNullOrWhiteSpace($candidateWindow.FirstSeenTimestamp) -and
                -not [string]::IsNullOrWhiteSpace($candidateWindow.LastSeenTimestamp)
            ) {
                $mergeThreshold = ([datetime]$currentWindow.LastSeenTimestamp).AddDays($AllowedGapDays + 1).ToString('yyyy-MM-dd')
                if ([datetime]$candidateWindow.FirstSeenTimestamp -le [datetime]$mergeThreshold) {
                    $shouldMerge = $true
                }
            }

            if ($shouldMerge) {
                $merged = Copy-VulnRecord -Record $candidate
                $merged.FirstSeenTimestamp = Get-MinVulnDate -Primary $currentWindow.FirstSeenTimestamp -Secondary $candidateWindow.FirstSeenTimestamp
                $merged.LastSeenTimestamp = Get-MaxVulnDate -Primary $currentWindow.LastSeenTimestamp -Secondary $candidateWindow.LastSeenTimestamp
                $current = $merged
                continue
            }

            $mergedRows.Add($current)
            $current = Copy-VulnRecord -Record $candidate
        }

        $mergedRows.Add($current)
    }

    return @($mergedRows)
}

function Write-MergedVulnObservedWindowRows {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$Source,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 30)]
        [int]$AllowedGapDays = 1,

        [Parameter(Mandatory = $false)]
        [ref]$InputRowCount = ([ref]0),

        [Parameter(Mandatory = $false)]
        [ref]$OutputRowCount = ([ref]0)
    )

    $rowsByIdentity = @{}
    $sourceRowCount = 0
    $mergedRowCount = 0

    foreach ($row in (& $Source)) {
        if ($null -eq $row) { continue }

        $sourceRowCount++
        $identityKey = Get-VulnObservedWindowIdentityKey -Row $row
        if (-not $rowsByIdentity.ContainsKey($identityKey)) {
            $rowsByIdentity[$identityKey] = [System.Collections.Generic.List[object]]::new()
        }
        $rowsByIdentity[$identityKey].Add($row)
    }

    foreach ($identityKey in @($rowsByIdentity.Keys | Sort-Object)) {
        foreach ($mergedRow in @(Merge-VulnObservedWindowRows -Rows @($rowsByIdentity[$identityKey]) -AllowedGapDays $AllowedGapDays)) {
            $mergedRowCount++
            Write-Output $mergedRow
        }

        [void]$rowsByIdentity.Remove($identityKey)
    }

    $InputRowCount.Value = $sourceRowCount
    $OutputRowCount.Value = $mergedRowCount
}

function Read-NormalizedVulnStoreRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 30)]
        [int]$AllowedGapDays = 1
    )

    $normalizedStoreBasePath = $BasePath
    foreach ($row in Write-MergedVulnObservedWindowRows -Source { Read-VulnStoreRow -BasePath $normalizedStoreBasePath } -AllowedGapDays $AllowedGapDays) {
        Write-Output $row
    }
}

function Get-NormalizationSourceRows {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DataPath,

        [Parameter(Mandatory = $false)]
        [switch]$SkipObservedWindowMerge
    )

    if (Test-VulnStoreExistence -BasePath $DataPath) {
        Write-Information '  Found vulnerability current/history store to normalize...' -InformationAction Continue
        if ($SkipObservedWindowMerge) {
            Write-Information '  Synthetic stress dataset detected; skipping observed-window merge.' -InformationAction Continue
            foreach ($row in Read-VulnStoreRow -BasePath $DataPath) {
                if ($null -ne $row) {
                    Write-Output $row
                }
            }
            return
        }

        try {
            $observedWindowCachePath = Publish-VulnObservedWindowCache -BasePath $DataPath
            if (-not [string]::IsNullOrWhiteSpace($observedWindowCachePath) -and (Test-Path -LiteralPath $observedWindowCachePath -PathType Leaf)) {
                Write-Information ("  Using observed-window cache {0}" -f (Split-Path -Leaf $observedWindowCachePath)) -InformationAction Continue
                foreach ($row in Read-VulnNdjsonRecordsFromPath -Path $observedWindowCachePath) {
                    if ($null -ne $row) {
                        Write-Output $row
                    }
                }
                return
            }
        }
        catch {
            Write-Warning "  Observed-window cache build failed; falling back to live merge. $_"
        }

        $inputRowCount = 0
        $normalizedRowCount = 0
        foreach ($row in Write-MergedVulnObservedWindowRows -Source { Read-VulnStoreRow -BasePath $DataPath } -InputRowCount ([ref]$inputRowCount) -OutputRowCount ([ref]$normalizedRowCount)) {
            Write-Output $row
        }

        if ($normalizedRowCount -ne $inputRowCount) {
            Write-Information ("  Collapsed {0} vulnerability observation row(s) into {1} normalized window(s)" -f $inputRowCount, $normalizedRowCount) -InformationAction Continue
        }
        return
    }

    $legacyFiles = @(Get-VulnLegacySnapshotFile -BasePath $DataPath)
    if ($legacyFiles.Count -eq 0) { throw "No VulnExport snapshot files found in '$DataPath'." }

    $legacyStore = Convert-LegacyVulnSnapshotsToStore -BasePath $DataPath
    Write-Information "  Found $($legacyFiles.Count) legacy export file(s); canonicalizing in memory for normalization..." -InformationAction Continue

    if ($SkipObservedWindowMerge) {
        Write-Information '  Synthetic stress dataset detected; skipping observed-window merge.' -InformationAction Continue
        foreach ($record in @($legacyStore.CurrentRecords)) {
            if ($null -ne $record) {
                Write-Output $record
            }
        }
        foreach ($historyDocument in @($legacyStore.HistoryDocuments)) {
            foreach ($snapshot in @($historyDocument.snapshots)) {
                foreach ($entry in @($snapshot.closed)) {
                    $historyRow = Get-VulnPropertyValue -InputObject $entry -Name 'row'
                    if ($null -ne $historyRow) {
                        Write-Output $historyRow
                    }
                }
            }
        }
        return
    }

    $legacyInputRowCount = 0
    $legacyNormalizedRowCount = 0
    foreach ($row in Write-MergedVulnObservedWindowRows -Source {
        foreach ($record in @($legacyStore.CurrentRecords)) {
            if ($null -ne $record) {
                Write-Output $record
            }
        }

        foreach ($historyDocument in @($legacyStore.HistoryDocuments)) {
            foreach ($snapshot in @($historyDocument.snapshots)) {
                foreach ($entry in @($snapshot.closed)) {
                    $historyRow = Get-VulnPropertyValue -InputObject $entry -Name 'row'
                    if ($null -ne $historyRow) {
                        Write-Output $historyRow
                    }
                }
            }
        }
    } -InputRowCount ([ref]$legacyInputRowCount) -OutputRowCount ([ref]$legacyNormalizedRowCount)) {
        Write-Output $row
    }

    if ($legacyNormalizedRowCount -ne $legacyInputRowCount) {
        Write-Information ("  Collapsed {0} vulnerability observation row(s) into {1} normalized window(s)" -f $legacyInputRowCount, $legacyNormalizedRowCount) -InformationAction Continue
    }
}

function ConvertTo-NormalizedData {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DataPath,

        [Parameter(Mandatory = $true)]
        [string]$VulnOutputPath,

        [Parameter(Mandatory = $false)]
        [string]$VulnColumnDirectoryPath,

        [Parameter(Mandatory = $true)]
        [hashtable]$Machines,

        [Parameter(Mandatory = $false)]
        [hashtable]$AdvancedHuntingData = @{},

        [Parameter(Mandatory = $false)]
        [switch]$SkipObservedWindowMerge
    )

    Write-Information '  Normalizing data structure...' -InformationAction Continue
    Write-Information ("  Normalization inputs: {0} machine(s), {1} Advanced Hunting CVE(s)" -f $Machines.Count, $AdvancedHuntingData.Count) -InformationAction Continue
    $context = Get-NormalizationContext
    $lookups = $context.Lookups
    $vendorIndex = $context.Indexes.vendors
    $exploitIndex = $context.Indexes.exploitLevels
    $groupIndex = $context.Indexes.groups
    $platformIndex = $context.Indexes.platforms
    $tagIndex = $context.Indexes.tags
    $updateIndex = $context.Indexes.updates
    $deviceIndex = $context.Indexes.devices
    $softwareIndex = $context.Indexes.software
    $cveIndex = $context.Indexes.cves
    $versionIndex = $context.Indexes.versions
    $dateIndex = $context.Indexes.dates
    $diskPathIndex = $context.Indexes.diskPaths
    $regPathIndex = $context.Indexes.regPaths
    $affSoftwareIndex = $context.Indexes.affSoftware
    $batchTitleIndex = $context.Indexes.batchTitles

    $firstLastSwappedCount = 0
    $processedCount = 0
    $hasNoTags = $false
    $vulnWriter = $null
    $jsonWriter = $null
    $columnWriterSet = $null
    $vulnColumnPaths = $null
    $syntheticManifestPath = Join-Path $DataPath 'synthetic-manifest.json'
    $effectiveSkipObservedWindowMerge = ($SkipObservedWindowMerge -or (Test-Path -LiteralPath $syntheticManifestPath -PathType Leaf))
    $contentStoreExists = (Test-VulnContentStoreExistence -BasePath $DataPath)
    $storeExists = ((Test-VulnStoreExistence -BasePath $DataPath) -or $contentStoreExists)
    $useRawStoreFastPath = ($effectiveSkipObservedWindowMerge -and $storeExists)
    $useContentStoreFastPath = ($useRawStoreFastPath -and $contentStoreExists)

    if ($useRawStoreFastPath) {
        if ($useContentStoreFastPath) {
            Write-Information '  Synthetic stress dataset detected; using content-store normalization fast path.' -InformationAction Continue
            $rawNormalizationResult = Invoke-ContentStoreNormalization -DataPath $DataPath -VulnOutputPath $VulnOutputPath -VulnColumnDirectoryPath $VulnColumnDirectoryPath -Context $context -Machines $Machines -AdvancedHuntingData $AdvancedHuntingData
        }
        else {
            Write-Information '  Synthetic stress dataset detected; using raw store normalization fast path.' -InformationAction Continue
            $rawNormalizationResult = Invoke-RawStoreNormalization -DataPath $DataPath -VulnOutputPath $VulnOutputPath -VulnColumnDirectoryPath $VulnColumnDirectoryPath -Context $context -Machines $Machines -AdvancedHuntingData $AdvancedHuntingData
        }
        $processedCount = [int]$rawNormalizationResult.ProcessedCount
        $firstLastSwappedCount = [int]$rawNormalizationResult.FirstLastSwappedCount
        $hasNoTags = ($rawNormalizationResult.HasNoTags -eq $true)
        $vulnColumnPaths = $rawNormalizationResult.VulnColumnPaths
    }
    else {
        if (-not [string]::IsNullOrWhiteSpace($VulnColumnDirectoryPath)) {
            $columnWriterSet = Open-CompactVulnColumnWriterSet -DirectoryPath $VulnColumnDirectoryPath
            $vulnColumnPaths = $columnWriterSet.Paths
        }

        try {
            if (-not $columnWriterSet) {
                $vulnWriter = [System.IO.StreamWriter]::new($VulnOutputPath, $false, [System.Text.UTF8Encoding]::new($false))
                $jsonWriter = [Newtonsoft.Json.JsonTextWriter]::new($vulnWriter)
                $jsonWriter.Formatting = [Newtonsoft.Json.Formatting]::None
                $jsonWriter.WriteStartArray()
            }

            foreach ($v in Get-NormalizationSourceRows -DataPath $DataPath -SkipObservedWindowMerge:$effectiveSkipObservedWindowMerge) {
                if ($v.PSObject.Properties['IsOnboarded']?.Value -ne $true) { continue }
                $processedCount++

                $deviceId = [string]$v.DeviceId
                $machine = $Machines[$deviceId]
                $fallbackDeviceName = $v.PSObject.Properties['DeviceName']?.Value
                $fallbackGroupName = $v.PSObject.Properties['RbacGroupName']?.Value
                $fallbackPlatform = $v.PSObject.Properties['OSPlatform']?.Value
                $fallbackOsVersion = $v.PSObject.Properties['OSVersion']?.Value
                $deviceKey = if (-not [string]::IsNullOrWhiteSpace($deviceId)) {
                    $deviceId
                }
                else {
                    @(
                        [string]$fallbackDeviceName
                        [string]$fallbackGroupName
                        [string]$fallbackPlatform
                        [string]$fallbackOsVersion
                    ) -join '|'
                }

            if (-not $deviceIndex.ContainsKey($deviceKey)) {
                    # Prefer the stable DeviceId whenever it exists. Only fall back to
                    # row-level metadata when the export truly lacks a device identifier.
                    $groupName = if ($machine) { $machine.PSObject.Properties['rbacGroupName']?.Value } else { $fallbackGroupName }
                    if ([string]::IsNullOrWhiteSpace([string]$groupName)) {
                        $groupName = if ([string]::IsNullOrWhiteSpace([string]$fallbackGroupName)) { '(none)' } else { $fallbackGroupName }
                    }
                    $groupIdx = Get-OrCreateIndex -value $groupName -list $lookups.groups -indexMap $groupIndex

                    $osPlat = if ($machine) { $machine.PSObject.Properties['osPlatform']?.Value } else { $fallbackPlatform }
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

                    $deviceIndex[$deviceKey] = $lookups.devices.Count

                    $machineInfo = $null
                    if ($machine) {
                        $machineLastSeen = $machine.PSObject.Properties['lastSeen']?.Value
                        $machineFirstSeen = $machine.PSObject.Properties['firstSeen']?.Value
                        $machineInfo = [PSCustomObject]@{
                            ip = $machine.PSObject.Properties['lastIpAddress']?.Value
                            eip = $machine.PSObject.Properties['lastExternalIpAddress']?.Value
                            hs = $machine.PSObject.Properties['healthStatus']?.Value
                            rs = $machine.PSObject.Properties['riskScore']?.Value
                            el = $machine.PSObject.Properties['exposureLevel']?.Value
                            dv = $machine.PSObject.Properties['deviceValue']?.Value
                            mb = $machine.PSObject.Properties['managedBy']?.Value
                            aad = $machine.PSObject.Properties['isAadJoined']?.Value
                            ls = Get-NormalizationCachedYmdDate -Context $context -DateValue $machineLastSeen
                            fs = Get-NormalizationCachedYmdDate -Context $context -DateValue $machineFirstSeen
                        }
                    }

                    $lookups.devices.Add([PSCustomObject]@{
                        id = $deviceId
                        n = if ($machine) { $machine.PSObject.Properties['computerDnsName']?.Value } elseif ($fallbackDeviceName) { $fallbackDeviceName } else { '(no machine data)' }
                        g = $groupIdx
                        o = $platIdx
                        ov = if ($machine) { $machine.PSObject.Properties['osVersion']?.Value } else { $fallbackOsVersion }
                        t = $tagIndices
                        m = $machineInfo
                    })
            }
            $devIdx = $deviceIndex[$deviceKey]

            $vendorIdx = Get-OrCreateIndex -value $v.PSObject.Properties['SoftwareVendor']?.Value -list $lookups.vendors -indexMap $vendorIndex

            $softwareVendor = $v.PSObject.Properties['SoftwareVendor']?.Value ?? ''
            $softwareName = $v.PSObject.Properties['SoftwareName']?.Value ?? ''
            $recommendationReference = $v.PSObject.Properties['RecommendationReference']?.Value ?? ''
            $softwareKey = "$softwareVendor|$softwareName|$recommendationReference"
            if (-not $softwareIndex.ContainsKey($softwareKey)) {
                $softwareIndex[$softwareKey] = $lookups.software.Count
                $lookups.software.Add([PSCustomObject]@{
                    v = $vendorIdx
                    n = $softwareName
                    r = $recommendationReference
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
            $cveKey = @(
                [string]$cveId,
                [string]$cvssScore,
                [string]$sevLevel,
                [string]$exploitabilityLevel,
                [string]$cveBatchUrl,
                [string]$btValue
            ) -join '|'

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
                        id = $cveId
                        sc = $cvssScore
                        sv = $sevIdx
                        ex = $expIdx
                        u = $cveBatchUrl
                        bt = $btIdx
                        pd = $publishedDate
                        desc = $vulnDescription
                        ep = $epssScore
                        as = $affSoftwareIndices
                    })
            }
            $cveIdx = $cveIndex[$cveKey]

            $recUpdate = $v.PSObject.Properties['RecommendedSecurityUpdate']?.Value
            $recUpdateId = $v.PSObject.Properties['RecommendedSecurityUpdateId']?.Value
            $recUpdateUrl = $v.PSObject.Properties['RecommendedSecurityUpdateUrl']?.Value
            $updateName = if ($recUpdate -and $recUpdate -ne '--') { $recUpdate } else { $null }
            if ($null -eq $updateName -or $updateName -eq '') {
                $updIdx = -1
            }
            else {
                $updateKey = @(
                    [string]$updateName,
                    [string]$recUpdateId,
                    [string]$recUpdateUrl
                ) -join '|'
                if ($updateIndex.ContainsKey($updateKey)) {
                    $updIdx = $updateIndex[$updateKey]
                }
                else {
                    $updIdx = $lookups.updates.Count
                    $updateIndex[$updateKey] = $updIdx
                    $lookups.updates.Add([PSCustomObject]@{
                        n = $updateName
                        id = $recUpdateId
                        url = $recUpdateUrl
                    })
                }
            }

            $seenWindow = Get-NormalizedVulnSeenWindow `
                -FirstSeenValue $v.PSObject.Properties['FirstSeenTimestamp']?.Value `
                -LastSeenValue $v.PSObject.Properties['LastSeenTimestamp']?.Value
            $firstSeen = if ($seenWindow.FirstSeenTimestamp) { Get-NormalizationCachedYmdDate -Context $context -DateValue $seenWindow.FirstSeenTimestamp } else { $null }
            $lastSeen = if ($seenWindow.LastSeenTimestamp) { Get-NormalizationCachedYmdDate -Context $context -DateValue $seenWindow.LastSeenTimestamp } else { $null }
            if ($seenWindow.WasReordered) {
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
            $compactRecord = New-Object object[] 10
            $compactRecord[0] = $devIdx
            $compactRecord[1] = $cveIdx
            $compactRecord[2] = $swIdx
            $compactRecord[3] = $versionIdx
            $compactRecord[4] = $firstSeenIdx
            $compactRecord[5] = $lastSeenIdx
            $compactRecord[6] = [int]($secUpdateAvail -eq $true)
            $compactRecord[7] = $updIdx
            $compactRecord[8] = $diskPathIndices
            $compactRecord[9] = $regPathIndices

            if ($columnWriterSet) {
                Write-CompactVulnRecordColumnSet -WriterSet $columnWriterSet -Record $compactRecord
            }
            else {
                $jsonWriter.WriteStartArray()
                foreach ($compactValue in $compactRecord) {
                    if ($null -eq $compactValue) {
                        $jsonWriter.WriteNull()
                        continue
                    }

                    if ($compactValue -is [System.Collections.IEnumerable] -and $compactValue -isnot [string]) {
                        $jsonWriter.WriteStartArray()
                        foreach ($nestedValue in $compactValue) {
                            if ($null -eq $nestedValue) {
                                $jsonWriter.WriteNull()
                            }
                            else {
                                $jsonWriter.WriteValue($nestedValue)
                            }
                        }
                        $jsonWriter.WriteEndArray()
                        continue
                    }

                    $jsonWriter.WriteValue($compactValue)
                }
                $jsonWriter.WriteEndArray()
            }

            if (($processedCount % 50000) -eq 0) {
                Write-Information ("  Processed {0} onboarded vulnerability record(s)..." -f $processedCount) -InformationAction Continue
            }

            if (($processedCount % 100000) -eq 0) {
                if ($columnWriterSet) {
                    Sync-CompactVulnColumnWriterSet -WriterSet $columnWriterSet
                }
                else {
                    $jsonWriter.Flush()
                }
                Invoke-FullGarbageCollection
            }
        }

            if ($columnWriterSet) {
                Sync-CompactVulnColumnWriterSet -WriterSet $columnWriterSet
            }
            else {
                $jsonWriter.WriteEndArray()
                $jsonWriter.Flush()
            }
        }
        finally {
            if ($jsonWriter) {
                $jsonWriter.Close()
            }
            if ($vulnWriter) {
                $vulnWriter.Dispose()
            }
            if ($columnWriterSet) {
                Close-CompactVulnColumnWriterSet -WriterSet $columnWriterSet
            }
        }
    }

    if ($processedCount -eq 0) { throw 'No onboarded vulnerabilities found after streaming all export files.' }
    Write-Information "  Loaded $processedCount onboarded vulnerability records" -InformationAction Continue

    $noTagsLabel = '(No Tags)'
    if ($hasNoTags -and -not $tagIndex.ContainsKey($noTagsLabel)) {
        $tagIndex[$noTagsLabel] = $lookups.tags.Count
        $lookups.tags.Add($noTagsLabel)
    }
    $noTagsIdx = if ($tagIndex.ContainsKey($noTagsLabel)) { $tagIndex[$noTagsLabel] } else { -1 }

    Write-Information "  Normalized: $($lookups.devices.Count) devices, $($lookups.cves.Count) CVEs, $($lookups.software.Count) software, $($lookups.vendors.Count) vendors" -InformationAction Continue
    if ($firstLastSwappedCount -gt 0) {
        Write-Warning "  Corrected $firstLastSwappedCount record(s) with FirstSeenTimestamp > LastSeenTimestamp"
    }

    $datasetVendors = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($vendor in $lookups.vendors) {
        [void]$datasetVendors.Add((Get-VendorMatchKey -Vendor $vendor))
    }

    foreach ($cve in $lookups.cves) {
        if ($null -ne $cve.as -and $cve.as.Count -gt 0) {
            $filteredIndices = [System.Collections.Generic.List[int]]::new()
            foreach ($asIdx in $cve.as) {
                $swStr = $lookups.affSoftware[$asIdx]
                $separatorIndex = $swStr.IndexOf(':')
                $swVendor = if ($separatorIndex -ge 0) { $swStr.Substring(0, $separatorIndex) } else { $swStr }
                if ($datasetVendors.Contains((Get-VendorMatchKey -Vendor $swVendor))) {
                    $filteredIndices.Add($asIdx)
                }
            }
            $cve.as = if ($filteredIndices.Count -gt 0) { $filteredIndices } else { $null }
        }
    }

    return @{
        Lookups = [PSCustomObject]@{
            vendors = $lookups.vendors
            severities = $lookups.severities
            exploitLevels = $lookups.exploitLevels
            groups = $lookups.groups
            platforms = $lookups.platforms
            tags = $lookups.tags
            updates = $lookups.updates
            versions = $lookups.versions
            dates = $lookups.dates
            diskPaths = $lookups.diskPaths
            regPaths = $lookups.regPaths
            affSoftware = $lookups.affSoftware
            batchTitles = $lookups.batchTitles
            devices = $lookups.devices
            software = $lookups.software
            cves = $lookups.cves
            noTagsIdx = $noTagsIdx
        }
        Quality = [PSCustomObject]@{
            FirstLastSwappedCount = $firstLastSwappedCount
        }
        VulnCount = $processedCount
        VulnsPath = if ($columnWriterSet) { $null } else { $VulnOutputPath }
        VulnColumnPaths = $vulnColumnPaths
    }
}
