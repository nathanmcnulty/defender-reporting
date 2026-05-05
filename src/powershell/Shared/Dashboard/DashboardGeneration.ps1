# Shared generator/runbook helpers used for dashboard normalization and HTML assembly.

function Get-DashboardTemplateContent {
    <#
    .SYNOPSIS
        Reads dashboard template files from the templates directory.

    .DESCRIPTION
        Reads the HTML, CSS, and JavaScript template files and returns their content.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$TemplatesPath,

        [Parameter(Mandatory = $true)]
        [string]$DefaultRootPath
    )

    $templatesDirectory = if (-not [string]::IsNullOrWhiteSpace($TemplatesPath)) {
        $TemplatesPath
    }
    else {
        Join-Path -Path $DefaultRootPath -ChildPath 'templates'
    }

    $templates = @{
        Html = $null
        Css = $null
        Js = $null
    }

    $htmlPath = Join-Path -Path $templatesDirectory -ChildPath 'dashboard.html'
    $cssPath = Join-Path -Path $templatesDirectory -ChildPath 'dashboard.css'
    $jsPath = Join-Path -Path $templatesDirectory -ChildPath 'dashboard.js'

    if (Test-Path -Path $htmlPath) {
        Write-Host '  Loading HTML template...' -ForegroundColor Gray
        $templates.Html = Get-Content -Path $htmlPath -Raw
    }
    else {
        throw "Template file not found: $htmlPath"
    }

    if (Test-Path -Path $cssPath) {
        Write-Host '  Loading CSS template...' -ForegroundColor Gray
        $templates.Css = Get-Content -Path $cssPath -Raw
    }
    else {
        throw "Template file not found: $cssPath"
    }

    if (Test-Path -Path $jsPath) {
        Write-Host '  Loading JavaScript template...' -ForegroundColor Gray
        $templates.Js = Get-Content -Path $jsPath -Raw
    }
    else {
        throw "Template file not found: $jsPath"
    }

    return $templates
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
            $cachedLibrary = Get-Item -LiteralPath $cachePath
            if ($cachedLibrary.Length -le 0) {
                Write-Warning "Cached $Name library was empty; refreshing."
                Remove-Item -LiteralPath $cachePath -Force -ErrorAction SilentlyContinue
            }
            else {
                Copy-Item -LiteralPath $cachePath -Destination $OutputPath -Force
                Write-Information "Reusing cached $Name library" -InformationAction Continue
                return $OutputPath
            }
        }
    }

    Write-Information "Downloading $Name library..." -InformationAction Continue

    try {
        Invoke-WebRequest -Uri $Url -OutFile $OutputPath -TimeoutSec 30
        $downloadedLibrary = Get-Item -LiteralPath $OutputPath -ErrorAction Stop
        if ($downloadedLibrary.Length -le 0) {
            throw "$Name library download produced an empty file."
        }

        if ($cachePath) {
            Copy-Item -LiteralPath $OutputPath -Destination $cachePath -Force
        }
        Write-Information "  $Name downloaded successfully" -InformationAction Continue
        return $OutputPath
    }
    catch {
        if (Test-Path -LiteralPath $OutputPath -PathType Leaf) {
            Remove-Item -LiteralPath $OutputPath -Force -ErrorAction SilentlyContinue
        }

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

function Write-Base64CharBuffer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.TextWriter]$Writer,

        [Parameter(Mandatory = $true)]
        [char[]]$Chars,

        [Parameter(Mandatory = $true)]
        [int]$Count,

        [Parameter(Mandatory = $true)]
        [ref]$CurrentLineLength,

        [Parameter(Mandatory = $false)]
        [switch]$InsertLineBreaks
    )

    if ($Count -le 0) {
        return
    }

    if (-not $InsertLineBreaks) {
        $Writer.Write($Chars, 0, $Count)
        return
    }

    $offset = 0
    $lineLength = [int]$CurrentLineLength.Value
    while ($offset -lt $Count) {
        $remainingOnLine = 76 - $lineLength
        if ($remainingOnLine -le 0) {
            $Writer.Write("`r`n")
            $lineLength = 0
            $remainingOnLine = 76
        }

        $charsToWrite = [System.Math]::Min($remainingOnLine, $Count - $offset)
        $Writer.Write($Chars, $offset, $charsToWrite)
        $offset += $charsToWrite
        $lineLength += $charsToWrite

        if ($lineLength -eq 76 -and $offset -lt $Count) {
            $Writer.Write("`r`n")
            $lineLength = 0
        }
    }

    $CurrentLineLength.Value = $lineLength
}

function Write-Base64FileContent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.TextWriter]$Writer,

        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $false)]
        [switch]$InsertLineBreaks
    )

    $inputBlockByteCount = 57 * 128
    $inputBuffer = [byte[]]::new($inputBlockByteCount + 2)
    $base64CharBuffer = [char[]]::new([int]([System.Math]::Ceiling($inputBuffer.Length / 3.0) * 4))
    $currentLineLength = 0
    $pendingByteCount = 0
    $stream = $null

    try {
        $stream = [System.IO.File]::OpenRead($FilePath)
        while (($bytesRead = $stream.Read($inputBuffer, $pendingByteCount, $inputBlockByteCount)) -gt 0) {
            $totalByteCount = $pendingByteCount + $bytesRead
            $bytesToEncode = if ($stream.Position -lt $stream.Length) {
                $totalByteCount - ($totalByteCount % 3)
            }
            else {
                $totalByteCount
            }

            if ($bytesToEncode -le 0) {
                $pendingByteCount = $totalByteCount
                continue
            }

            $base64CharCount = [System.Convert]::ToBase64CharArray($inputBuffer, 0, $bytesToEncode, $base64CharBuffer, 0)
            Write-Base64CharBuffer -Writer $Writer -Chars $base64CharBuffer -Count $base64CharCount -CurrentLineLength ([ref]$currentLineLength) -InsertLineBreaks:$InsertLineBreaks

            $pendingByteCount = $totalByteCount - $bytesToEncode
            if ($pendingByteCount -gt 0) {
                [System.Array]::Copy($inputBuffer, $bytesToEncode, $inputBuffer, 0, $pendingByteCount)
            }
        }

        if ($pendingByteCount -gt 0) {
            $base64CharCount = [System.Convert]::ToBase64CharArray($inputBuffer, 0, $pendingByteCount, $base64CharBuffer, 0)
            Write-Base64CharBuffer -Writer $Writer -Chars $base64CharBuffer -Count $base64CharCount -CurrentLineLength ([ref]$currentLineLength) -InsertLineBreaks:$InsertLineBreaks
        }
    }
    finally {
        if ($stream) {
            $stream.Dispose()
        }
    }
}

function Get-Base64FileContent {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $false)]
        [switch]$InsertLineBreaks
    )

    $bytes = [System.IO.File]::ReadAllBytes($FilePath)
    $formatting = if ($InsertLineBreaks) { [System.Base64FormattingOptions]::InsertLineBreaks } else { [System.Base64FormattingOptions]::None }
    return [System.Convert]::ToBase64String($bytes, $formatting)
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
        $wroteNoteProperties = $false
        foreach ($property in $Value.PSObject.Properties) {
            if ($property.MemberType -ne [System.Management.Automation.PSMemberTypes]::NoteProperty) {
                continue
            }

            if (-not $wroteNoteProperties) {
                $Writer.WriteStartObject()
                $wroteNoteProperties = $true
            }

            $Writer.WritePropertyName([string]$property.Name)
            Write-JsonValueToWriter -Writer $Writer -Value $property.Value
        }

        if ($wroteNoteProperties) {
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

function Get-NormalizedLookupPropertyValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Value,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [System.Collections.IDictionary]) {
        return $Value[$Name]
    }

    $property = $Value.PSObject.Properties[$Name]
    if ($null -ne $property) {
        return $property.Value
    }

    return $null
}

function Set-NormalizedLookupPropertyValue {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal helper updates in-memory lookup state during payload finalization.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Lookups,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Value
    )

    if ($Lookups -is [System.Collections.IDictionary]) {
        $Lookups[$Name] = $Value
        return
    }

    $property = $Lookups.PSObject.Properties[$Name]
    if ($null -ne $property) {
        $property.Value = $Value
        return
    }

    Add-Member -InputObject $Lookups -NotePropertyName $Name -NotePropertyValue $Value -Force
}

function Get-NormalizedLookupCount {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Lookups,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $value = Get-NormalizedLookupPropertyValue -Value $Lookups -Name $Name
    if ($null -eq $value) {
        return 0
    }

    if ($value -is [System.Collections.ICollection]) {
        return [int]$value.Count
    }

    return [int]@($value).Count
}

function Get-NormalizedLookupCountSummary {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Lookups
    )

    return [PSCustomObject]@{
        DeviceCount = Get-NormalizedLookupCount -Lookups $Lookups -Name 'devices'
        CveCount = Get-NormalizedLookupCount -Lookups $Lookups -Name 'cves'
        SoftwareCount = Get-NormalizedLookupCount -Lookups $Lookups -Name 'software'
        VendorCount = Get-NormalizedLookupCount -Lookups $Lookups -Name 'vendors'
    }
}

function Write-NormalizedDeviceMachineInfoToWriter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Newtonsoft.Json.JsonTextWriter]$Writer,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$MachineInfo
    )

    if ($null -eq $MachineInfo) {
        $Writer.WriteNull()
        return
    }

    $Writer.WriteStartObject()
    foreach ($propertyName in @('ip', 'eip', 'u', 'hs', 'rs', 'el', 'dv', 'mb', 'aad', 'ls', 'fs')) {
        $Writer.WritePropertyName($propertyName)
        Write-JsonValueToWriter -Writer $Writer -Value (Get-NormalizedLookupPropertyValue -Value $MachineInfo -Name $propertyName)
    }
    $Writer.WriteEndObject()
}

function Write-NormalizedDeviceLookupsToWriter {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Newtonsoft.Json.JsonTextWriter]$Writer,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Devices
    )

    if ($null -eq $Devices) {
        $Writer.WriteNull()
        return
    }

    $Writer.WriteStartArray()
    foreach ($device in $Devices) {
        if ($null -eq $device) {
            $Writer.WriteNull()
            continue
        }

        $Writer.WriteStartObject()
        foreach ($propertyName in @('id', 'n', 'g', 'o', 'ov', 't')) {
            $Writer.WritePropertyName($propertyName)
            Write-JsonValueToWriter -Writer $Writer -Value (Get-NormalizedLookupPropertyValue -Value $device -Name $propertyName)
        }
        $Writer.WritePropertyName('m')
        Write-NormalizedDeviceMachineInfoToWriter -Writer $Writer -MachineInfo (Get-NormalizedLookupPropertyValue -Value $device -Name 'm')
        $Writer.WriteEndObject()
    }
    $Writer.WriteEndArray()
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
    foreach ($columnName in @('d', 'c', 's', 'v', 'f', 'l', 'ua', 'u', 'dp', 'rp', 'iv')) {
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

    $columnOrder = @('d', 'c', 's', 'v', 'f', 'l', 'ua', 'u', 'dp', 'rp', 'iv')
    $columnStates = [object[]]::new(11)
    for ($i = 0; $i -lt 11; $i++) {
        $columnStates[$i] = $writers[$columnOrder[$i]]
    }

    return [PSCustomObject]@{
        DirectoryPath = $DirectoryPath
        Paths = $paths
        Writers = $writers
        ColumnStates = $columnStates
    }
}

function Write-CompactVulnRecordColumnSet {
    param(
        [pscustomobject]$WriterSet,
        [object[]]$Record
    )

    if ($null -eq $Record) {
        throw 'Compact vulnerability record cannot be null.'
    }

    $states = $WriterSet.ColumnStates
    for ($i = 0; $i -lt 11; $i++) {
        $col = $states[$i]
        $val = $Record[$i]
        $buf = $col.Buffer

        if ($col.HasValue) { [void]$buf.Append(',') } else { $col.HasValue = $true }

        if ($null -eq $val) {
            [void]$buf.Append('null')
        }
        elseif ($val -is [System.Collections.IEnumerable] -and $val -isnot [string]) {
            [void]$buf.Append('[')
            $isFirst = $true
            foreach ($nv in $val) {
                if ($isFirst) { $isFirst = $false } else { [void]$buf.Append(',') }
                if ($null -eq $nv) { [void]$buf.Append('null') } else { [void]$buf.Append([string]$nv) }
            }
            [void]$buf.Append(']')
        }
        else {
            [void]$buf.Append([string]$val)
        }

        if ($buf.Length -ge 131072) {
            $col.StreamWriter.Write($buf.ToString())
            [void]$buf.Clear()
        }
    }
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

function Open-CompactJsonArrayReader {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $resolvedPath = [System.IO.Path]::GetFullPath($Path)
    $streamReader = [System.IO.StreamReader]::new($resolvedPath, [System.Text.Encoding]::UTF8)
    $jsonReader = [Newtonsoft.Json.JsonTextReader]::new($streamReader)
    if (-not $jsonReader.Read() -or $jsonReader.TokenType -ne [Newtonsoft.Json.JsonToken]::StartArray) {
        $jsonReader.Dispose()
        $streamReader.Dispose()
        throw "Expected JSON array in '$resolvedPath'."
    }

    return [PSCustomObject]@{
        Path = $resolvedPath
        StreamReader = $streamReader
        JsonReader = $jsonReader
    }
}

function Read-NextCompactJsonArrayValue {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$ReaderState
    )

    $jsonReader = $ReaderState.JsonReader
    while ($jsonReader.Read()) {
        if ($jsonReader.TokenType -eq [Newtonsoft.Json.JsonToken]::EndArray) {
            return [PSCustomObject]@{
                HasValue = $false
                Value = $null
            }
        }

        return [PSCustomObject]@{
            HasValue = $true
            Value = (Read-CompactJsonReaderValue -Reader $jsonReader)
        }
    }

    throw "Unexpected end of compact JSON array '$($ReaderState.Path)'."
}

function Skip-JsonReaderValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Newtonsoft.Json.JsonTextReader]$Reader
    )

    if ($Reader.TokenType -ne [Newtonsoft.Json.JsonToken]::StartArray -and
        $Reader.TokenType -ne [Newtonsoft.Json.JsonToken]::StartObject) {
        return
    }

    $depth = 1
    while ($depth -gt 0 -and $Reader.Read()) {
        switch ($Reader.TokenType) {
            ([Newtonsoft.Json.JsonToken]::StartArray) { $depth++ }
            ([Newtonsoft.Json.JsonToken]::StartObject) { $depth++ }
            ([Newtonsoft.Json.JsonToken]::EndArray) { $depth-- }
            ([Newtonsoft.Json.JsonToken]::EndObject) { $depth-- }
        }
    }
}

function Get-JsonReaderArrayElementCount {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [Newtonsoft.Json.JsonTextReader]$Reader,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ($Reader.TokenType -ne [Newtonsoft.Json.JsonToken]::StartArray) {
        throw "Expected JSON array in '$Path', found '$($Reader.TokenType)'."
    }

    $count = 0
    while ($Reader.Read()) {
        if ($Reader.TokenType -eq [Newtonsoft.Json.JsonToken]::EndArray) {
            break
        }

        Skip-JsonReaderValue -Reader $Reader
        $count++
    }

    return $count
}

function Get-PayloadVulnCountFromJsonReader {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [Newtonsoft.Json.JsonTextReader]$Reader,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not $Reader.Read() -or $Reader.TokenType -ne [Newtonsoft.Json.JsonToken]::StartObject) {
        throw "Expected JSON object payload in '$Path'."
    }

    $vulnsFormat = $null
    while ($Reader.Read()) {
        if ($Reader.TokenType -eq [Newtonsoft.Json.JsonToken]::EndObject) {
            break
        }

        if ($Reader.TokenType -ne [Newtonsoft.Json.JsonToken]::PropertyName) {
            continue
        }

        $propertyName = [string]$Reader.Value
        if (-not $Reader.Read()) {
            throw "Unexpected end of payload while reading '$Path'."
        }

        if ($propertyName -eq 'vulnsFormat') {
            $vulnsFormat = [string]$Reader.Value
            continue
        }

        if ($propertyName -ne 'vulns') {
            Skip-JsonReaderValue -Reader $Reader
            continue
        }

        if ($Reader.TokenType -eq [Newtonsoft.Json.JsonToken]::StartArray) {
            return (Get-JsonReaderArrayElementCount -Reader $Reader -Path $Path)
        }

        if ($Reader.TokenType -ne [Newtonsoft.Json.JsonToken]::StartObject) {
            throw "Expected 'vulns' property in '$Path' to be an array or object, found '$($Reader.TokenType)'."
        }

        while ($Reader.Read()) {
            if ($Reader.TokenType -eq [Newtonsoft.Json.JsonToken]::EndObject) {
                break
            }

            if ($Reader.TokenType -ne [Newtonsoft.Json.JsonToken]::PropertyName) {
                continue
            }

            $columnName = [string]$Reader.Value
            if (-not $Reader.Read()) {
                throw "Unexpected end of payload while reading vuln columns in '$Path'."
            }

            if ($columnName -eq 'd') {
                return (Get-JsonReaderArrayElementCount -Reader $Reader -Path $Path)
            }

            Skip-JsonReaderValue -Reader $Reader
        }

        if ($vulnsFormat) {
            throw "Unable to locate vuln count column for payload format '$vulnsFormat' in '$Path'."
        }

        throw "Unable to locate vulnerability rows in '$Path'."
    }

    return 0
}

function Get-CompressedPayloadVulnCount {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $fileStream = $null
    $gzip = $null
    $reader = $null
    $jsonReader = $null

    try {
        $fileStream = [System.IO.File]::OpenRead($Path)
        $gzip = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Decompress)
        $reader = [System.IO.StreamReader]::new($gzip, [System.Text.Encoding]::UTF8)
        $jsonReader = [Newtonsoft.Json.JsonTextReader]::new($reader)
        return (Get-PayloadVulnCountFromJsonReader -Reader $jsonReader -Path $Path)
    }
    finally {
        if ($jsonReader) { $jsonReader.Close() }
        elseif ($reader) { $reader.Dispose() }
        elseif ($gzip) { $gzip.Dispose() }
        elseif ($fileStream) { $fileStream.Dispose() }
    }
}

function Get-DashboardHtmlScriptContent {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Html,

        [Parameter(Mandatory = $true)]
        [string]$ScriptId
    )

    $pattern = '<script\s+id="' + [regex]::Escape($ScriptId) + '"[^>]*>(?<content>.*?)</script>'
    $match = [regex]::Match(
        $Html,
        $pattern,
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Singleline
    )

    if (-not $match.Success) {
        return ''
    }

    return $match.Groups['content'].Value.Trim()
}

function Get-DashboardEmbeddedPayloadTempPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HtmlPath
    )

    $resolvedPath = [System.IO.Path]::GetFullPath($HtmlPath)
    $content = [System.IO.File]::ReadAllText($resolvedPath, [System.Text.Encoding]::UTF8)
    $dataFormat = Get-DashboardHtmlScriptContent -Html $content -ScriptId 'dataFormat'

    if ($dataFormat -eq 'external-compressed') {
        $dashboardConfigJson = Get-DashboardHtmlScriptContent -Html $content -ScriptId 'dashboardConfig'
        if ([string]::IsNullOrWhiteSpace($dashboardConfigJson)) {
            throw "Unable to locate dashboardConfig metadata in '$HtmlPath'."
        }

        $dashboardConfig = $dashboardConfigJson | ConvertFrom-Json -Depth 20
        $payloadUrl = [string]$dashboardConfig.payloadUrl
        if ([string]::IsNullOrWhiteSpace($payloadUrl)) {
            throw "dashboardConfig in '$HtmlPath' does not define payloadUrl."
        }

        $htmlDirectory = Split-Path -Path $resolvedPath -Parent
        $payloadRelativePath = $payloadUrl.Replace('/', '\')
        return [System.IO.Path]::GetFullPath((Join-Path $htmlDirectory $payloadRelativePath))
    }

    $startMarker = '<script id="vulnsData" type="application/json">'
    $endMarker = '</script>'
    $startIndex = $content.IndexOf($startMarker)
    if ($startIndex -lt 0) {
        throw "Unable to locate embedded vulnerability payload in '$HtmlPath'."
    }

    $payloadStart = $startIndex + $startMarker.Length
    $payloadEnd = $content.IndexOf($endMarker, $payloadStart)
    if ($payloadEnd -lt 0) {
        throw "Unable to locate payload terminator in '$HtmlPath'."
    }

    $base64 = ($content.Substring($payloadStart, $payloadEnd - $payloadStart) -replace '\s+', '')
    $bytes = [Convert]::FromBase64String($base64)
    $tempPayloadPath = Join-Path ([System.IO.Path]::GetTempPath()) ('dashboard-embedded-payload-' + [guid]::NewGuid().ToString('N') + '.json.gz')
    [System.IO.File]::WriteAllBytes($tempPayloadPath, $bytes)
    return $tempPayloadPath
}

function Get-DashboardEmbeddedPayloadInspection {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $resolvedPath = [System.IO.Path]::GetFullPath($Path)
    $content = [System.IO.File]::ReadAllText($resolvedPath, [System.Text.Encoding]::UTF8)
    $dataFormat = Get-DashboardHtmlScriptContent -Html $content -ScriptId 'dataFormat'

    if ($dataFormat -eq 'external-compressed') {
        $dashboardConfigJson = Get-DashboardHtmlScriptContent -Html $content -ScriptId 'dashboardConfig'
        if ([string]::IsNullOrWhiteSpace($dashboardConfigJson)) {
            throw "Unable to locate dashboardConfig metadata in '$Path'."
        }

        $dashboardConfig = $dashboardConfigJson | ConvertFrom-Json -Depth 20
        $payloadUrl = [string]$dashboardConfig.payloadUrl
        if ([string]::IsNullOrWhiteSpace($payloadUrl)) {
            throw "dashboardConfig in '$Path' does not define payloadUrl."
        }

        $htmlDirectory = Split-Path -Path $resolvedPath -Parent
        $payloadRelativePath = $payloadUrl.Replace('/', '\')
        $payloadPath = [System.IO.Path]::GetFullPath((Join-Path $htmlDirectory $payloadRelativePath))
        return [PSCustomObject]@{
            DataFormat = $dataFormat
            PayloadPath = $payloadPath
            PayloadRowCount = (Get-CompressedPayloadVulnCount -Path $payloadPath)
            PayloadSha256 = (Get-FileSha256Hex -Path $payloadPath)
        }
    }

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

    $base64 = ($content.Substring($payloadStart, $payloadEnd - $payloadStart) -replace '\s+', '')
    $bytes = [Convert]::FromBase64String($base64)
    $stream = $null
    $gzip = $null
    $reader = $null
    $jsonReader = $null

    try {
        $stream = [System.IO.MemoryStream]::new($bytes, $false)
        $gzip = [System.IO.Compression.GZipStream]::new($stream, [System.IO.Compression.CompressionMode]::Decompress)
        $reader = [System.IO.StreamReader]::new($gzip, [System.Text.Encoding]::UTF8)
        $jsonReader = [Newtonsoft.Json.JsonTextReader]::new($reader)
        $payloadRowCount = Get-PayloadVulnCountFromJsonReader -Reader $jsonReader -Path $Path
    }
    finally {
        if ($jsonReader) { $jsonReader.Close() }
        elseif ($reader) { $reader.Dispose() }
        elseif ($gzip) { $gzip.Dispose() }
        elseif ($stream) { $stream.Dispose() }
    }

    $payloadSha256 = ([System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::HashData($bytes))).Replace('-', '').ToLowerInvariant()
    return [PSCustomObject]@{
        DataFormat = $dataFormat
        PayloadPath = $null
        PayloadRowCount = $payloadRowCount
        PayloadSha256 = $payloadSha256
    }
}

function Get-EmbeddedDashboardPayloadVulnCount {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return [int](Get-DashboardEmbeddedPayloadInspection -Path $Path).PayloadRowCount
}

function Get-DashboardPayloadGzipSha256 {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return [string](Get-DashboardEmbeddedPayloadInspection -Path $Path).PayloadSha256
}

function Get-NormalizedAuditDecimalString {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) {
        return ''
    }

    $raw = [string]$Value
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return ''
    }

    [decimal]$decimalValue = 0
    if ([decimal]::TryParse($raw, [ref]$decimalValue)) {
        return $decimalValue.ToString('0.#####', [System.Globalization.CultureInfo]::InvariantCulture)
    }

    return $raw.Trim()
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

            $rowValues = New-Object object[] 11
            for ($fieldIndex = 0; $fieldIndex -lt 11; $fieldIndex++) {
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
            Write-CompactColumnFileValue -WriterState $ColumnWriters.iv -Value $rowValues[10]
        }
    }
    finally {
        if ($jsonReader) { $jsonReader.Close() }
        if ($reader) { $reader.Dispose() }
    }
}

function Get-CompactVulnJsonRowCount {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $reader = $null
    $jsonReader = $null
    $rowCount = 0

    try {
        $reader = [System.IO.StreamReader]::new($Path, [System.Text.Encoding]::UTF8)
        $jsonReader = [Newtonsoft.Json.JsonTextReader]::new($reader)

        if (-not $jsonReader.Read() -or $jsonReader.TokenType -ne [Newtonsoft.Json.JsonToken]::StartArray) {
            throw "Expected compact vulnerability JSON '$Path' to start with a JSON array."
        }

        while ($jsonReader.Read()) {
            if ($jsonReader.TokenType -eq [Newtonsoft.Json.JsonToken]::EndArray) {
                break
            }

            if ($jsonReader.TokenType -ne [Newtonsoft.Json.JsonToken]::StartArray) {
                throw "Expected compact vulnerability row array in '$Path', found '$($jsonReader.TokenType)'."
            }

            Skip-JsonReaderValue -Reader $jsonReader
            $rowCount++
        }

        return $rowCount
    }
    finally {
        if ($jsonReader) { $jsonReader.Close() }
        if ($reader) { $reader.Dispose() }
    }
}

function Write-CombinedPayloadLookups {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Newtonsoft.Json.JsonTextWriter]$Writer,

        [Parameter(Mandatory = $true)]
        [object]$Lookups,

        [Parameter(Mandatory = $false)]
        [switch]$ConsumeLookups
    )

    $Writer.WritePropertyName('lookups')
    Write-CombinedPayloadLookupsValue -Writer $Writer -Lookups $Lookups -ConsumeLookups:$ConsumeLookups
}

function Write-CombinedPayloadLookupsValue {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Newtonsoft.Json.JsonTextWriter]$Writer,

        [Parameter(Mandatory = $true)]
        [object]$Lookups,

        [Parameter(Mandatory = $false)]
        [switch]$ConsumeLookups
    )

    $Writer.WriteStartObject()
    foreach ($lookupPropertyName in @(
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
            'inventory',
            'software',
            'cves',
            'noTagsIdx'
        )) {
        $Writer.WritePropertyName($lookupPropertyName)
        if ($Lookups -is [System.Collections.IDictionary]) {
            $lookupValue = $Lookups[$lookupPropertyName]
        }
        else {
            $lookupValue = $Lookups.PSObject.Properties[$lookupPropertyName].Value
        }
        if ($lookupPropertyName -eq 'devices') {
            Write-NormalizedDeviceLookupsToWriter -Writer $Writer -Devices $lookupValue
        }
        else {
            Write-JsonValueToWriter -Writer $Writer -Value $lookupValue
        }

        if ($ConsumeLookups) {
            Set-NormalizedLookupPropertyValue -Lookups $Lookups -Name $lookupPropertyName -Value $null
            if ($lookupPropertyName -in @('devices', 'inventory', 'software', 'cves')) {
                Invoke-FullGarbageCollection
            }
        }
    }
    $Writer.WriteEndObject()
}

function Open-CombinedPayloadWriter {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [string]$VulnsFormat
    )

    $fileStream = $null
    $gzipStream = $null
    $writer = $null
    $jsonWriter = $null

    try {
        $fileStream = [System.IO.File]::Create($OutputPath)
        $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionLevel]::Fastest)
        $writer = [System.IO.StreamWriter]::new($gzipStream, [System.Text.UTF8Encoding]::new($false))
        $jsonWriter = [Newtonsoft.Json.JsonTextWriter]::new($writer)
        $jsonWriter.Formatting = [Newtonsoft.Json.Formatting]::None
        $jsonWriter.WriteStartObject()
        $jsonWriter.WritePropertyName('vulnsFormat')
        $jsonWriter.WriteValue($VulnsFormat)
        $jsonWriter.WritePropertyName('vulns')

        return [PSCustomObject]@{
            OutputPath = $OutputPath
            FileStream = $fileStream
            GzipStream = $gzipStream
            StreamWriter = $writer
            JsonWriter = $jsonWriter
        }
    }
    catch {
        if ($jsonWriter) { $jsonWriter.Close() }
        elseif ($writer) { $writer.Dispose() }
        elseif ($gzipStream) { $gzipStream.Dispose() }
        elseif ($fileStream) { $fileStream.Dispose() }
        throw
    }
}

function Close-CombinedPayloadWriter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$WriterState,

        [Parameter(Mandatory = $true)]
        [object]$Lookups,

        [Parameter(Mandatory = $false)]
        [switch]$ConsumeLookups
    )

    try {
        Update-NormalizedAffectedSoftwareLookup -Lookups $Lookups
        Write-CombinedPayloadLookups -Writer $WriterState.JsonWriter -Lookups $Lookups -ConsumeLookups:$ConsumeLookups
        $WriterState.JsonWriter.WriteEndObject()
        $WriterState.JsonWriter.Flush()
    }
    finally {
        if ($WriterState.JsonWriter) { $WriterState.JsonWriter.Close() }
        elseif ($WriterState.StreamWriter) { $WriterState.StreamWriter.Dispose() }
        elseif ($WriterState.GzipStream) { $WriterState.GzipStream.Dispose() }
        elseif ($WriterState.FileStream) { $WriterState.FileStream.Dispose() }
    }
}

function Update-NormalizedAffectedSoftwareLookup {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal helper only mutates in-memory lookup data before serialization.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Lookups
    )

    if ($null -eq $Lookups) {
        return
    }

    $vendors = $null
    $cves = $null
    $affSoftware = $null
    if ($Lookups -is [System.Collections.IDictionary]) {
        $vendors = $Lookups['vendors']
        $cves = $Lookups['cves']
        $affSoftware = $Lookups['affSoftware']
    }
    else {
        $vendors = $Lookups.PSObject.Properties['vendors']?.Value
        $cves = $Lookups.PSObject.Properties['cves']?.Value
        $affSoftware = $Lookups.PSObject.Properties['affSoftware']?.Value
    }

    if ($null -eq $vendors -or $null -eq $cves -or $null -eq $affSoftware) {
        return
    }

    $datasetVendors = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($vendor in @($vendors)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$vendor)) {
            [void]$datasetVendors.Add((Get-VendorMatchKey -Vendor $vendor))
        }
    }

    $affectedSoftwareLookupCount = @($affSoftware).Count
    foreach ($cve in @($cves)) {
        if ($null -eq $cve -or $null -eq $cve.as -or @($cve.as).Count -eq 0) {
            continue
        }

        $filteredIndices = [System.Collections.Generic.List[int]]::new()
        foreach ($asIdx in @($cve.as)) {
            $resolvedIndex = -1
            try {
                $resolvedIndex = [int]$asIdx
            }
            catch {
                continue
            }

            if ($resolvedIndex -lt 0 -or $resolvedIndex -ge $affectedSoftwareLookupCount) {
                continue
            }

            $swStr = [string]$affSoftware[$resolvedIndex]
            if ([string]::IsNullOrWhiteSpace($swStr)) {
                continue
            }

            $separatorIndex = $swStr.IndexOf(':')
            $swVendor = if ($separatorIndex -ge 0) { $swStr.Substring(0, $separatorIndex) } else { $swStr }
            if ($datasetVendors.Contains((Get-VendorMatchKey -Vendor $swVendor))) {
                $filteredIndices.Add($resolvedIndex)
            }
        }

        $cve.as = if ($filteredIndices.Count -gt 0) { $filteredIndices } else { $null }
    }
}

function Open-NormalizedVulnWriter {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$VulnOutputPath,

        [Parameter(Mandatory = $false)]
        [string]$VulnColumnDirectoryPath,

        [Parameter(Mandatory = $false)]
        [string]$PayloadOutputPath
    )

    if (-not [string]::IsNullOrWhiteSpace($PayloadOutputPath)) {
        $payloadWriter = Open-CombinedPayloadWriter -OutputPath $PayloadOutputPath -VulnsFormat 'rows-v1'
        $payloadWriter.JsonWriter.WriteStartArray()
        return [PSCustomObject]@{
            Mode = 'payload'
            JsonWriter = $payloadWriter.JsonWriter
            PayloadWriter = $payloadWriter
            PayloadPath = $PayloadOutputPath
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($VulnColumnDirectoryPath)) {
        $columnWriterSet = Open-CompactVulnColumnWriterSet -DirectoryPath $VulnColumnDirectoryPath
        return [PSCustomObject]@{
            Mode = 'column'
            ColumnWriterSet = $columnWriterSet
            VulnColumnPaths = $columnWriterSet.Paths
        }
    }

    $vulnWriter = [System.IO.StreamWriter]::new($VulnOutputPath, $false, [System.Text.UTF8Encoding]::new($false))
    $jsonWriter = [Newtonsoft.Json.JsonTextWriter]::new($vulnWriter)
    $jsonWriter.Formatting = [Newtonsoft.Json.Formatting]::None
    $jsonWriter.WriteStartArray()
    return [PSCustomObject]@{
        Mode = 'rows'
        JsonWriter = $jsonWriter
        VulnWriter = $vulnWriter
        VulnsPath = $VulnOutputPath
    }
}

function Write-NormalizedCompactRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$WriterState,

        [Parameter(Mandatory = $true)]
        [object]$Record
    )

    if ($WriterState.Mode -eq 'column') {
        Write-CompactVulnRecordColumnSet -WriterSet $WriterState.ColumnWriterSet -Record $Record
        return
    }

    Write-CompactVulnRecordJson -Writer $WriterState.JsonWriter -Record $Record
}

function Sync-NormalizedVulnWriter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$WriterState
    )

    if ($WriterState.Mode -eq 'column') {
        Sync-CompactVulnColumnWriterSet -WriterSet $WriterState.ColumnWriterSet
        return
    }

    if ($WriterState.JsonWriter) {
        $WriterState.JsonWriter.Flush()
    }
}

function Close-NormalizedVulnWriter {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$WriterState,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Lookups,

        [Parameter(Mandatory = $false)]
        [switch]$ConsumeLookups
    )

    if ($WriterState.Mode -eq 'column') {
        Sync-CompactVulnColumnWriterSet -WriterSet $WriterState.ColumnWriterSet
        Close-CompactVulnColumnWriterSet -WriterSet $WriterState.ColumnWriterSet
        return [PSCustomObject]@{
            Mode = 'column'
            VulnsPath = $null
            VulnColumnPaths = $WriterState.VulnColumnPaths
            PayloadPath = $null
        }
    }

    if ($WriterState.Mode -eq 'payload') {
        $WriterState.JsonWriter.WriteEndArray()
        Close-CombinedPayloadWriter -WriterState $WriterState.PayloadWriter -Lookups $Lookups -ConsumeLookups:$ConsumeLookups
        return [PSCustomObject]@{
            Mode = 'payload'
            VulnsPath = $null
            VulnColumnPaths = $null
            PayloadPath = $WriterState.PayloadPath
        }
    }

    try {
        $WriterState.JsonWriter.WriteEndArray()
        $WriterState.JsonWriter.Flush()
    }
    finally {
        if ($WriterState.JsonWriter) {
            $WriterState.JsonWriter.Close()
        }
        if ($WriterState.VulnWriter) {
            $WriterState.VulnWriter.Dispose()
        }
    }

    return [PSCustomObject]@{
        Mode = 'rows'
        VulnsPath = $WriterState.VulnsPath
        VulnColumnPaths = $null
        PayloadPath = $null
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

    $payloadWriter = $null
    $columnReaders = [System.Collections.Generic.List[System.IDisposable]]::new()
    $jsonWriter = $null
    $activeColumnPaths = $null

    try {
        $payloadWriter = Open-CombinedPayloadWriter -OutputPath $OutputPath -VulnsFormat $(if ($VulnColumnPaths) { 'columns-v1' } else { 'rows-v1' })
        $jsonWriter = $payloadWriter.JsonWriter

        if ($VulnColumnPaths) {
            $activeColumnPaths = $VulnColumnPaths
            $jsonWriter.WriteStartObject()
            foreach ($columnName in @('d', 'c', 's', 'v', 'f', 'l', 'ua', 'u', 'dp', 'rp', 'iv')) {
                $jsonWriter.WritePropertyName($columnName)
                $columnReader = [System.IO.StreamReader]::new([string]$activeColumnPaths[$columnName], [System.Text.Encoding]::UTF8)
                $columnJsonReader = [Newtonsoft.Json.JsonTextReader]::new($columnReader)
                [void]$columnReaders.Add($columnJsonReader)
                [void]$columnReaders.Add($columnReader)
                $jsonWriter.WriteToken($columnJsonReader)
            }
            $jsonWriter.WriteEndObject()
        }
        else {
            if ([string]::IsNullOrWhiteSpace($VulnsPath) -or -not (Test-Path -LiteralPath $VulnsPath -PathType Leaf)) {
                throw 'Write-CombinedPayloadGzip requires either -VulnsPath or -VulnColumnPaths.'
            }

            $vulnsReader = [System.IO.StreamReader]::new($VulnsPath, [System.Text.Encoding]::UTF8)
            $vulnsJsonReader = [Newtonsoft.Json.JsonTextReader]::new($vulnsReader)
            [void]$columnReaders.Add($vulnsJsonReader)
            [void]$columnReaders.Add($vulnsReader)
            $jsonWriter.WriteToken($vulnsJsonReader)
        }

        Close-CombinedPayloadWriter -WriterState $payloadWriter -Lookups $Lookups
        $payloadWriter = $null
    }
    finally {
        foreach ($columnDisposable in $columnReaders) {
            $columnDisposable.Dispose()
        }
        if ($payloadWriter) {
            Close-CombinedPayloadWriter -WriterState $payloadWriter -Lookups $Lookups
        }
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
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [switch]$InsertBase64LineBreaks
    )

    $writer = $null
    try {
        $writer = [System.IO.StreamWriter]::new($OutputPath, $false, [System.Text.UTF8Encoding]::new($false))
        $position = 0
        foreach ($segment in $Segments) {
            $placeholder = $segment.Placeholder
            $index = $Template.IndexOf($placeholder, $position, [System.StringComparison]::Ordinal)
            if ($index -lt 0) {
                throw "Template placeholder not found: $placeholder"
            }

            $writer.Write($Template.Substring($position, $index - $position))
            if ($segment.ContainsKey('Base64FilePath')) {
                Write-Base64FileContent -Writer $writer -FilePath $segment.Base64FilePath -InsertLineBreaks:$InsertBase64LineBreaks
            }
            elseif ($segment.ContainsKey('FilePath')) {
                $writer.Write([System.IO.File]::ReadAllText([string]$segment.FilePath, [System.Text.Encoding]::UTF8))
            }
            else {
                $writer.Write([string]$segment.Value)
            }

            $position = $index + $placeholder.Length
        }

        $writer.Write($Template.Substring($position))
    }
    finally {
        if ($writer) {
            $writer.Dispose()
        }
    }
}

function Write-Utf8File {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Content
    )

    [System.IO.File]::WriteAllText($Path, $Content, [System.Text.UTF8Encoding]::new($false))
}

function Get-DashboardAssetsDirectoryPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HtmlPath
    )

    $resolvedHtmlPath = [System.IO.Path]::GetFullPath($HtmlPath)
    $parentPath = Split-Path -Path $resolvedHtmlPath -Parent
    $assetsDirectoryName = ([System.IO.Path]::GetFileNameWithoutExtension($resolvedHtmlPath) + '.assets')
    return (Join-Path $parentPath $assetsDirectoryName)
}

function Get-DashboardAssetsDirectoryName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HtmlPath
    )

    return ([System.IO.Path]::GetFileNameWithoutExtension([System.IO.Path]::GetFullPath($HtmlPath)) + '.assets')
}

function Get-DashboardAssetUrl {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HtmlPath,

        [Parameter(Mandatory = $true)]
        [string]$AssetFileName
    )

    return ((Get-DashboardAssetsDirectoryName -HtmlPath $HtmlPath) + '/' + $AssetFileName)
}

function Write-DashboardArtifactBundle {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TemplateHtml,

        [Parameter(Mandatory = $true)]
        [string]$TemplateCss,

        [Parameter(Mandatory = $true)]
        [string]$TemplateJs,

        [Parameter(Mandatory = $true)]
        [string]$PakoLibraryPath,

        [Parameter(Mandatory = $true)]
        [string]$ChartJsLibraryPath,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$ChartJsBundlePath,

        [Parameter(Mandatory = $true)]
        [string]$PdfExportBundleSourcePath,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$PdfExportBundlePath,

        [Parameter(Mandatory = $true)]
        [string]$PayloadPath,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$LookupsJsonEscaped = '',

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$DataQualitySectionHtml = '',

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$DataQualityMetaScript = '',

        [Parameter(Mandatory = $false)]
        [bool]$SplitAssets = $false,

        [Parameter(Mandatory = $false)]
        [bool]$InsertBase64LineBreaks = $false
    )

    if (-not $SplitAssets) {
        if ([string]::IsNullOrWhiteSpace($ChartJsBundlePath) -or -not (Test-Path -LiteralPath $ChartJsBundlePath -PathType Leaf)) {
            throw 'Write-DashboardArtifactBundle requires ChartJsBundlePath when SplitAssets is false.'
        }

        if ([string]::IsNullOrWhiteSpace($PdfExportBundlePath) -or -not (Test-Path -LiteralPath $PdfExportBundlePath -PathType Leaf)) {
            throw 'Write-DashboardArtifactBundle requires PdfExportBundlePath when SplitAssets is false.'
        }
    }

    $dataFormatMarker = if ($SplitAssets) { 'external-compressed' } else { 'compressed' }
    $dashboardAssetsConfig = [ordered]@{
        deliveryMode = if ($SplitAssets) { 'split-assets' } else { 'self-contained' }
        chartJsMode = if ($SplitAssets) { 'external' } else { 'embedded' }
        pdfExportBundleMode = if ($SplitAssets) { 'external' } else { 'embedded' }
        debugLogging = $false
    }

    $cssBlock = $null
    $pakoBlock = $null
    $dashboardJsBlock = $null
    $vulnsDataSegment = $null
    $chartJsSegment = $null
    $pdfExportBundleSegment = $null
    $dashboardAssetsPath = $null

    if ($SplitAssets) {
        $dashboardAssetsPath = Get-DashboardAssetsDirectoryPath -HtmlPath $OutputPath
        [void](New-Item -Path $dashboardAssetsPath -ItemType Directory -Force)

        $cssAssetFileName = 'dashboard.css'
        $jsAssetFileName = 'dashboard.js'
        $pakoAssetFileName = 'pako.js'
        $chartJsAssetFileName = 'chart.js'
        $pdfBundleAssetFileName = 'pdf-export.bundle.js'
        $payloadAssetFileName = 'payload.json.gz'

        $cssAssetPath = Join-Path $dashboardAssetsPath $cssAssetFileName
        $jsAssetPath = Join-Path $dashboardAssetsPath $jsAssetFileName
        $pakoAssetPath = Join-Path $dashboardAssetsPath $pakoAssetFileName
        $chartJsAssetPath = Join-Path $dashboardAssetsPath $chartJsAssetFileName
        $pdfBundleAssetPath = Join-Path $dashboardAssetsPath $pdfBundleAssetFileName
        $payloadAssetPath = Join-Path $dashboardAssetsPath $payloadAssetFileName

        Write-Utf8File -Path $cssAssetPath -Content $TemplateCss
        Write-Utf8File -Path $jsAssetPath -Content $TemplateJs
        Copy-Item -LiteralPath $PakoLibraryPath -Destination $pakoAssetPath -Force
        Copy-Item -LiteralPath $ChartJsLibraryPath -Destination $chartJsAssetPath -Force
        Copy-Item -LiteralPath $PdfExportBundleSourcePath -Destination $pdfBundleAssetPath -Force
        Copy-Item -LiteralPath $PayloadPath -Destination $payloadAssetPath -Force

        $dashboardAssetsConfig.payloadUrl = Get-DashboardAssetUrl -HtmlPath $OutputPath -AssetFileName $payloadAssetFileName
        $dashboardAssetsConfig.chartJsUrl = Get-DashboardAssetUrl -HtmlPath $OutputPath -AssetFileName $chartJsAssetFileName
        $dashboardAssetsConfig.pdfExportBundleUrl = Get-DashboardAssetUrl -HtmlPath $OutputPath -AssetFileName $pdfBundleAssetFileName

        $cssBlock = '<link rel="stylesheet" href="' + (Get-DashboardAssetUrl -HtmlPath $OutputPath -AssetFileName $cssAssetFileName) + '">'
        $pakoBlock = '<script src="' + (Get-DashboardAssetUrl -HtmlPath $OutputPath -AssetFileName $pakoAssetFileName) + '"></script>'
        $dashboardJsBlock = '<script src="' + (Get-DashboardAssetUrl -HtmlPath $OutputPath -AssetFileName $jsAssetFileName) + '"></script>'
        $vulnsDataSegment = @{ Placeholder = '__VULNS_DATA__'; Value = '' }
        $chartJsSegment = @{ Placeholder = '__CHARTJS_CONTENT__'; Value = '' }
        $pdfExportBundleSegment = @{ Placeholder = '__PDF_EXPORT_BUNDLE_CONTENT__'; Value = '' }
    }
    else {
        $cssBlock = "<style>`r`n$TemplateCss`r`n    </style>"
        $pakoBlock = "<script>`r`n$(Get-Content -LiteralPath $PakoLibraryPath -Raw)`r`n    </script>"
        $dashboardJsBlock = "<script>`r`n$TemplateJs`r`n    </script>"
        $vulnsDataSegment = @{ Placeholder = '__VULNS_DATA__'; Base64FilePath = $PayloadPath }
        $chartJsSegment = @{ Placeholder = '__CHARTJS_CONTENT__'; Base64FilePath = $ChartJsBundlePath }
        $pdfExportBundleSegment = @{ Placeholder = '__PDF_EXPORT_BUNDLE_CONTENT__'; Base64FilePath = $PdfExportBundlePath }
    }

    $dashboardConfigJson = $dashboardAssetsConfig | ConvertTo-Json -Compress -Depth 20
    $segments = @(
        @{ Placeholder = '__CSS_BLOCK__'; Value = $cssBlock },
        @{ Placeholder = '__DATA_QUALITY_SECTION__'; Value = $DataQualitySectionHtml },
        @{ Placeholder = '__PAKO_BLOCK__'; Value = $pakoBlock },
        @{ Placeholder = '__DASHBOARD_CONFIG__'; Value = $dashboardConfigJson },
        @{ Placeholder = '__DATA_FORMAT__'; Value = $dataFormatMarker },
        @{ Placeholder = '__DATA_QUALITY_META_SCRIPT__'; Value = $DataQualityMetaScript },
        @{ Placeholder = '__LOOKUPS_DATA__'; Value = $LookupsJsonEscaped },
        $vulnsDataSegment,
        $chartJsSegment,
        $pdfExportBundleSegment,
        @{ Placeholder = '__DASHBOARD_JS_BLOCK__'; Value = $dashboardJsBlock }
    )

    Write-TemplatedHtml -Template $TemplateHtml -Segments $segments -OutputPath $OutputPath -InsertBase64LineBreaks:$InsertBase64LineBreaks

    return [PSCustomObject]@{
        OutputPath = $OutputPath
        AssetsPath = $dashboardAssetsPath
        DataFormat = $dataFormatMarker
        DeliveryMode = [string]$dashboardAssetsConfig.deliveryMode
    }
}

function Read-MachineData {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [switch]$AsNormalizationTuple
    )

    $asNormalizationTupleRequested = [bool]$AsNormalizationTuple
    $machineRecordReader = {
        param(
            [Parameter(Mandatory = $true)]
            [string]$SourcePath
        )

        if ($asNormalizationTupleRequested) {
            Read-MachineNormalizationEntriesFromFile -Path $SourcePath
        }
        else {
            Read-MachineRecordsFromFile -Path $SourcePath
        }
    }

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
            foreach ($record in (& $machineRecordReader $currentReadPath)) {
                if ($record.id) {
                    if ($record.PSObject.Properties['removed']?.Value -eq $true) {
                        $machines.Remove($record.id)
                        continue
                    }
                    $machineRecord = if ($asNormalizationTupleRequested) { $record.PSObject.Properties['tuple']?.Value } else { ConvertTo-CompactMachineRecord -Machine $record }
                    if ($null -eq $machineRecord) {
                        $machines.Remove($record.id)
                        continue
                    }
                    $machines[$record.id] = $machineRecord
                }
            }
        }
        elseif ($historySourcePaths.Count -gt 0) {
            Write-Information "  Reconstructing current state from $($historySourcePaths.Count) machine history source file(s)" -InformationAction Continue
            foreach ($sourcePath in $historySourcePaths) {
                foreach ($record in (& $machineRecordReader $sourcePath)) {
                    if ($record.id) {
                        if ($record.PSObject.Properties['removed']?.Value -eq $true) {
                            $machines.Remove($record.id)
                            continue
                        }
                        $machineRecord = if ($asNormalizationTupleRequested) { $record.PSObject.Properties['tuple']?.Value } else { ConvertTo-CompactMachineRecord -Machine $record }
                        if ($null -eq $machineRecord) {
                            $machines.Remove($record.id)
                            continue
                        }
                        $machines[$record.id] = $machineRecord
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
                foreach ($record in (& $machineRecordReader $file.FullName)) {
                    if ($record.id -and -not $machines.ContainsKey($record.id)) {
                        $machineRecord = if ($asNormalizationTupleRequested) { $record.PSObject.Properties['tuple']?.Value } else { ConvertTo-CompactMachineRecord -Machine $record }
                        if ($null -ne $machineRecord) {
                            $machines[$record.id] = $machineRecord
                        }
                    }
                }
            }
        }

        Write-Information "  Loaded $($machines.Count) unique machines" -InformationAction Continue
        return $machines
    }
}

function Read-NormalizationMachineLookup {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return (Read-MachineData -Path $Path -AsNormalizationTuple)
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

function Get-FileSetFingerprint {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Version,

        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo[]]$Files,

        [Parameter(Mandatory = $false)]
        [string[]]$MetadataLines,

        [Parameter(Mandatory = $false)]
        [ValidateSet('FullName', 'Name')]
        [string]$FileIdentityProperty = 'FullName'
    )

    $uniqueFiles = @($Files | Where-Object { $null -ne $_ } | Sort-Object FullName -Unique)
    if ($uniqueFiles.Count -eq 0) {
        return $null
    }

    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.AppendLine($Version)
    foreach ($line in @($MetadataLines)) {
        [void]$builder.AppendLine([string]$line)
    }

    foreach ($file in $uniqueFiles) {
        $hash = Get-FileSha256Hex -Path $file.FullName
        $fileIdentity = if ($FileIdentityProperty -eq 'Name') { $file.Name } else { $file.FullName }
        [void]$builder.Append($fileIdentity).Append('|')
        [void]$builder.Append($file.Length).Append('|')
        [void]$builder.AppendLine($hash)
    }

    $fingerprintBytes = [System.Text.Encoding]::UTF8.GetBytes($builder.ToString())
    $fingerprintHash = [System.Security.Cryptography.SHA256]::HashData($fingerprintBytes)
    return ([System.BitConverter]::ToString($fingerprintHash)).Replace('-', '').ToLowerInvariant()
}

function Sync-VulnContentStoreSidecar {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    if (Test-VulnContentStoreExistence -BasePath $BasePath) {
        return $true
    }

    if (-not (Test-VulnStoreExistence -BasePath $BasePath)) {
        return $false
    }

    try {
        Invoke-WithStoreLock -BasePath $BasePath -StoreName 'vuln' -ScriptBlock {
            Restore-StoreTransaction -BasePath $BasePath -StoreName 'vuln'

            if (-not (Test-VulnContentStoreExistence -BasePath $BasePath)) {
                Write-Information '  Rebuilding content-store sidecars from raw vulnerability store...' -InformationAction Continue
                Publish-VulnContentStoreUnlocked -BasePath $BasePath
            }
        } | Out-Null
    }
    catch {
        Write-Verbose "Vulnerability content sidecar rebuild failed; falling back to raw/object normalization. $_"
    }

    return (Test-VulnContentStoreExistence -BasePath $BasePath)
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
    $contentStoreExists = Sync-VulnContentStoreSidecar -BasePath $BasePath
    if ($contentStoreExists) {
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

    return (Get-FileSetFingerprint -Version 'observed-window-cache-v2' -Files @($sourceFiles) -MetadataLines @(
            ('AllowedGapDays=' + $AllowedGapDays)
            ('CacheShape=' + $(if ($contentStoreExists) { 'compact-ref-array-v1' } else { 'row-object-v1' }))
        ) -FileIdentityProperty Name)
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

function Write-MergedVulnContentStoreRefs {
    <#
    .SYNOPSIS
    Memory-efficient observed-window merge that operates on compact content-store
    ref arrays instead of fully-expanded PSCustomObjects. Each ref is a 5-element
    array [Id, DeviceProfileIdx, ContentTemplateIdx, FST, LST] — roughly 30x
    smaller per row than expanded objects.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 30)]
        [int]$AllowedGapDays = 1,

        [Parameter(Mandatory = $false)]
        [ValidateRange(4, 256)]
        [int]$PartitionCount = 128
    )

    # Collect ref file paths
    $refPaths = [System.Collections.Generic.List[string]]::new()
    $currentRefsPath = Get-VulnCurrentRefsPath -BasePath $BasePath
    if (Test-Path -LiteralPath $currentRefsPath -PathType Leaf) {
        $refPaths.Add($currentRefsPath)
    }
    foreach ($historyRefsFile in @(Get-ChildItem -Path $BasePath -Filter 'VulnHistoryRefs_*.json.gz' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
        $refPaths.Add($historyRefsFile.FullName)
    }

    if ($refPaths.Count -eq 0) { return }

    $partitionDir = Join-Path ([System.IO.Path]::GetTempPath()) ('owref-' + [System.Guid]::NewGuid().ToString('N'))
    [void](New-Item -ItemType Directory -Path $partitionDir -Force)

    $partitionWriters = [System.IO.StreamWriter[]]::new($PartitionCount)

    try {
        # Pass 1 — scatter raw ref lines to partition files by identity hash.
        # Use .NET StreamReader directly to avoid PowerShell pipeline buffering
        # that would materialize all 1.5M+ lines in memory at once.
        foreach ($refPath in $refPaths) {
            $refFileStream = [System.IO.File]::OpenRead($refPath)
            $refGzipStream = if ($refPath.EndsWith('.gz', [System.StringComparison]::OrdinalIgnoreCase)) {
                [System.IO.Compression.GZipStream]::new($refFileStream, [System.IO.Compression.CompressionMode]::Decompress)
            } else { $refFileStream }
            $refReader = [System.IO.StreamReader]::new($refGzipStream, [System.Text.UTF8Encoding]::new($false))
            try {
                while ($null -ne ($line = $refReader.ReadLine())) {
                    if ([string]::IsNullOrWhiteSpace($line)) { continue }

                # Fast Id extraction: ref lines are JSON arrays ["id",...
                $firstQuote = $line.IndexOf('"')
                if ($firstQuote -lt 0) { continue }
                $secondQuote = $line.IndexOf('"', $firstQuote + 1)
                if ($secondQuote -lt 0) { continue }
                $identityKey = $line.Substring($firstQuote + 1, $secondQuote - $firstQuote - 1)

                $hash = [uint32]([int64]$identityKey.GetHashCode() -band 0xFFFFFFFFL)
                $bucket = [int]($hash % [uint32]$PartitionCount)

                if ($null -eq $partitionWriters[$bucket]) {
                    $partPath = Join-Path $partitionDir "p$bucket.ndjson"
                    $partitionWriters[$bucket] = [System.IO.StreamWriter]::new(
                        [System.IO.File]::Create($partPath),
                        [System.Text.UTF8Encoding]::new($false))
                }
                $partitionWriters[$bucket].WriteLine($line)
                }
            }
            finally {
                $refReader.Dispose()
                if ($refGzipStream -ne $refFileStream) { $refGzipStream.Dispose() }
                $refFileStream.Dispose()
            }
        }

        for ($i = 0; $i -lt $PartitionCount; $i++) {
            if ($null -ne $partitionWriters[$i]) {
                $partitionWriters[$i].Dispose()
                $partitionWriters[$i] = $null
            }
        }

        # Pass 2 — gather: process each partition, merge refs by Id
        for ($bucket = 0; $bucket -lt $PartitionCount; $bucket++) {
            $partPath = Join-Path $partitionDir "p$bucket.ndjson"
            if (-not (Test-Path -LiteralPath $partPath -PathType Leaf)) { continue }

            $refsByIdentity = @{}
            foreach ($line in [System.IO.File]::ReadLines($partPath, [System.Text.UTF8Encoding]::new($false))) {
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                # Parse ref array via System.Text.Json (faster than ConvertFrom-Json)
                $doc = [System.Text.Json.JsonDocument]::Parse($line)
                try {
                    $arr = $doc.RootElement
                    $ref = @(
                        $arr[0].GetString()         # Id
                        $arr[1].GetInt32()           # DeviceProfileIdx
                        $arr[2].GetInt32()           # ContentTemplateIdx
                        $(if ($arr[3].ValueKind -eq [System.Text.Json.JsonValueKind]::Null) { $null } else { $arr[3].GetString() })  # FST
                        $(if ($arr[4].ValueKind -eq [System.Text.Json.JsonValueKind]::Null) { $null } else { $arr[4].GetString() })  # LST
                    )
                }
                finally { $doc.Dispose() }
                $identityKey = [string]$ref[0]
                if (-not $refsByIdentity.ContainsKey($identityKey)) {
                    $refsByIdentity[$identityKey] = [System.Collections.Generic.List[object]]::new()
                }
                $refsByIdentity[$identityKey].Add($ref)
            }

            foreach ($identityKey in @($refsByIdentity.Keys)) {
                $items = @($refsByIdentity[$identityKey] | Sort-Object { [string]$_[3] }, { [string]$_[4] })
                foreach ($mergedRef in @(Merge-VulnObservedWindowSequence `
                        -Items $items `
                        -AllowedGapDays $AllowedGapDays `
                        -GetWindow {
                            param($item)
                            Get-NormalizedVulnSeenWindow -FirstSeenValue ([string]$item[3]) -LastSeenValue ([string]$item[4])
                        } `
                        -CreateItem {
                            param($item)
                            [object[]]$item.Clone()
                        } `
                        -CreateMergedItem {
                            param($candidate, $firstSeenTimestamp, $lastSeenTimestamp)
                            $merged = [object[]]$candidate.Clone()
                            $merged[3] = $firstSeenTimestamp
                            $merged[4] = $lastSeenTimestamp
                            $merged
                        } `
                        -FinalizeItem {
                            param($item, $window)
                            $item[3] = $window.FirstSeenTimestamp
                            $item[4] = $window.LastSeenTimestamp
                            $item
                        })) {
                    ,$mergedRef
                }
            }

            $refsByIdentity.Clear()
            $refsByIdentity = $null
            Remove-Item -LiteralPath $partPath -Force -ErrorAction SilentlyContinue
        }
    }
    finally {
        for ($i = 0; $i -lt $PartitionCount; $i++) {
            if ($null -ne $partitionWriters[$i]) {
                $partitionWriters[$i].Dispose()
            }
        }
        if (Test-Path -LiteralPath $partitionDir) {
            Remove-Item -Recurse -Force -LiteralPath $partitionDir -ErrorAction SilentlyContinue
        }
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

        if (Test-VulnContentStoreExistence -BasePath $BasePath) {
            # Memory-efficient path: merge returns compact ref arrays. Write
            # raw JSON lines directly using StringBuilder to avoid 1.5M+
            # ConvertTo-Json calls.
            Write-MergedVulnContentStoreRefs -BasePath $BasePath -AllowedGapDays $AllowedGapDays | ForEach-Object {
                $ref = $_
                if ($null -eq $ref) { return }
                # Build JSON array string inline — refs are [id, dpIdx, ctIdx, fst, lst]
                $sb = [System.Text.StringBuilder]::new(128)
                [void]$sb.Append('["')
                [void]$sb.Append([string]$ref[0])
                [void]$sb.Append('",')
                [void]$sb.Append([string]$ref[1])
                [void]$sb.Append(',')
                [void]$sb.Append([string]$ref[2])
                [void]$sb.Append(',')
                $fst = $ref[3]; if ($null -eq $fst) { [void]$sb.Append('null') } else { [void]$sb.Append('"'); [void]$sb.Append([string]$fst); [void]$sb.Append('"') }
                [void]$sb.Append(',')
                $lst = $ref[4]; if ($null -eq $lst) { [void]$sb.Append('null') } else { [void]$sb.Append('"'); [void]$sb.Append([string]$lst); [void]$sb.Append('"') }
                [void]$sb.Append(']')
                $writer.WriteLine($sb.ToString())
            }
        }
        else {
            # IMPORTANT: Use pipeline (| ForEach-Object) not foreach() to avoid
            # collecting all merged rows into memory at once.
            $legacyCacheJsonOptions = [System.Text.Json.JsonSerializerOptions]::new()
            $legacyCacheJsonOptions.WriteIndented = $false
            $legacyCacheJsonOptions.MaxDepth = 20
            Write-MergedVulnObservedWindowRows -Source { Read-VulnStoreRow -BasePath $BasePath } -AllowedGapDays $AllowedGapDays | ForEach-Object {
                if ($null -eq $_) { return }
                $dict = [System.Collections.Generic.Dictionary[string,object]]::new()
                foreach ($prop in $_.PSObject.Properties) { $dict[$prop.Name] = $prop.Value }
                $writer.WriteLine([System.Text.Json.JsonSerializer]::Serialize($dict, $legacyCacheJsonOptions))
            }
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

function Get-NvdCveFingerprintSourceFileSet {
    [CmdletBinding()]
    [OutputType([System.IO.FileInfo[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    $currentPath = Get-NvdCveCurrentPath -BasePath $BasePath
    if (-not (Test-Path -LiteralPath $currentPath -PathType Leaf)) {
        return @()
    }

    return [System.IO.FileInfo[]]@((Get-Item -LiteralPath $currentPath))
}

function Get-DashboardSourceFileSummary {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.IO.FileInfo[]]$Files
    )

    $sourceFiles = @($Files | Where-Object { $null -ne $_ } | Sort-Object FullName)
    $latestFile = @($sourceFiles | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1)
    $latestLastWriteTimeUtc = if ($latestFile.Count -gt 0) { $latestFile[0].LastWriteTimeUtc.ToUniversalTime() } else { $null }
    $ageSeconds = if ($null -ne $latestLastWriteTimeUtc) {
        [math]::Max(0, [int][math]::Round(((Get-Date).ToUniversalTime() - $latestLastWriteTimeUtc).TotalSeconds, 0))
    }
    else {
        $null
    }

    return [PSCustomObject]@{
        Present = ($sourceFiles.Count -gt 0)
        FileCount = [int]$sourceFiles.Count
        LatestLastWriteTimeUtc = if ($null -ne $latestLastWriteTimeUtc) { $latestLastWriteTimeUtc.ToString('o') } else { $null }
        AgeSeconds = $ageSeconds
        Files = @($sourceFiles | ForEach-Object {
                [PSCustomObject]@{
                    Name = $_.Name
                    Length = [long]$_.Length
                    LastWriteTimeUtc = $_.LastWriteTimeUtc.ToUniversalTime().ToString('o')
                }
            })
    }
}

function Get-DashboardSourceSummary {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $false)]
        [int]$MachineCount = 0,

        [Parameter(Mandatory = $false)]
        [int]$AdvancedHuntingCveCount = 0,

        [Parameter(Mandatory = $false)]
        [int]$AdvancedHuntingDeviceUserCount = 0,

        [Parameter(Mandatory = $false)]
        [int]$AdvancedHuntingInventoryTupleCount = 0,

        [Parameter(Mandatory = $false)]
        [int]$NvdCveCount = 0,

        [Parameter(Mandatory = $false)]
        [string]$NormalizationMode = 'unknown',

        [Parameter(Mandatory = $false)]
        [switch]$SkipObservedWindowMerge
    )

    return [PSCustomObject]@{
        Version = 'dashboard-source-metadata-v1'
        GeneratedOnUtc = (Get-Date).ToUniversalTime().ToString('o')
        NormalizationMode = $NormalizationMode
        SkipObservedWindowMerge = ($SkipObservedWindowMerge -eq $true)
        MachineData = [PSCustomObject]@{
            RecordCount = [int]$MachineCount
            Source = Get-DashboardSourceFileSummary -Files (Get-MachineFingerprintSourceFileSet -BasePath $BasePath)
        }
        AdvancedHunting = [PSCustomObject]@{
            CveCount = [int]$AdvancedHuntingCveCount
            DeviceUserCount = [int]$AdvancedHuntingDeviceUserCount
            InventoryTupleCount = [int]$AdvancedHuntingInventoryTupleCount
            Source = Get-DashboardSourceFileSummary -Files (Get-AdvancedHuntingFingerprintSourceFileSet -BasePath $BasePath)
        }
        NvdCve = [PSCustomObject]@{
            RecordCount = [int]$NvdCveCount
            Source = Get-DashboardSourceFileSummary -Files (Get-NvdCveFingerprintSourceFileSet -BasePath $BasePath)
        }
    }
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

    $effectiveSkipObservedWindowMerge = ($SkipObservedWindowMerge -or (Test-IsSyntheticDataset -BasePath $BasePath))
    $files = [System.Collections.Generic.List[System.IO.FileInfo]]::new()

    $contentStoreExists = Sync-VulnContentStoreSidecar -BasePath $BasePath
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

function Get-NormalizedVulnColumnCacheFingerprint {
        [CmdletBinding()]
        [OutputType([string])]
        param(
            [Parameter(Mandatory = $true)]
            [string]$BasePath,

            [Parameter(Mandatory = $false)]
            [switch]$SkipObservedWindowMerge
        )

        if (-not (Sync-VulnContentStoreSidecar -BasePath $BasePath)) {
            return $null
        }

        $files = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
        foreach ($file in @(Get-VulnerabilityPayloadFingerprintSourceFileSet -BasePath $BasePath -SkipObservedWindowMerge:$SkipObservedWindowMerge)) {
            if ($null -ne $file) {
                $files.Add($file)
            }
        }

        if ($files.Count -eq 0) {
            return $null
        }

        return (Get-FileSetFingerprint -Version 'dashboard-vuln-column-cache-v1' -Files @($files) -MetadataLines @(
                ('SkipObservedWindowMerge=' + ($SkipObservedWindowMerge -eq $true))
            ))
}

function Get-NormalizedVulnColumnCacheDirectoryPath {
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

    $cacheDirectory = Get-DashboardCacheDirectory -BasePath $BasePath -ChildPath 'vuln-columns' -Create:$Create
    return Join-Path $cacheDirectory ("columns-{0}" -f $Fingerprint)
}

function Get-NormalizedVulnColumnCacheManifestPath {
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

    $cacheDirectory = Get-DashboardCacheDirectory -BasePath $BasePath -ChildPath 'vuln-columns' -Create:$Create
    return Join-Path $cacheDirectory ("columns-{0}.json" -f $Fingerprint)
}

function Get-NormalizedVulnColumnCacheColumnPaths {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Internal helper intentionally returns the full set of normalized vulnerability column paths.')]
        [CmdletBinding()]
        [OutputType([hashtable])]
        param(
            [Parameter(Mandatory = $true)]
            [string]$DirectoryPath
        )

        $paths = [ordered]@{}
        foreach ($columnName in @('d', 'c', 's', 'v', 'f', 'l', 'ua', 'u', 'dp', 'rp', 'iv')) {
            $paths[$columnName] = Join-Path $DirectoryPath ($columnName + '.json')
        }

    return $paths
}

function Clear-StaleNormalizedVulnColumnCache {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [string]$BasePath,

            [Parameter(Mandatory = $false)]
            [string[]]$KeepPaths = @()
        )

        $cacheDirectory = Get-DashboardCacheDirectory -BasePath $BasePath -ChildPath 'vuln-columns'
        if (-not (Test-Path -LiteralPath $cacheDirectory -PathType Container)) {
            return
        }

        $normalizedKeepPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($keepPath in @($KeepPaths)) {
            if (-not [string]::IsNullOrWhiteSpace($keepPath)) {
                [void]$normalizedKeepPaths.Add([System.IO.Path]::GetFullPath($keepPath))
            }
        }

    foreach ($cacheItem in @(Get-ChildItem -Path $cacheDirectory -Force -ErrorAction SilentlyContinue)) {
        if ($normalizedKeepPaths.Contains($cacheItem.FullName)) {
            continue
        }

        Remove-Item -LiteralPath $cacheItem.FullName -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Get-NormalizedVulnColumnCacheEntry {
        [CmdletBinding()]
        [OutputType([pscustomobject])]
        param(
            [Parameter(Mandatory = $true)]
            [string]$BasePath,

            [Parameter(Mandatory = $false)]
            [switch]$SkipObservedWindowMerge
        )

        $fingerprint = Get-NormalizedVulnColumnCacheFingerprint -BasePath $BasePath -SkipObservedWindowMerge:$SkipObservedWindowMerge
        if ([string]::IsNullOrWhiteSpace($fingerprint)) {
            return $null
        }

        $columnDirectoryPath = Get-NormalizedVulnColumnCacheDirectoryPath -BasePath $BasePath -Fingerprint $fingerprint -Create
        $manifestPath = Get-NormalizedVulnColumnCacheManifestPath -BasePath $BasePath -Fingerprint $fingerprint -Create
        if ((-not (Test-Path -LiteralPath $columnDirectoryPath -PathType Container)) -or (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf))) {
            return $null
        }

        $columnPaths = Get-NormalizedVulnColumnCacheColumnPaths -DirectoryPath $columnDirectoryPath
        foreach ($columnPath in $columnPaths.Values) {
            if (-not (Test-Path -LiteralPath ([string]$columnPath) -PathType Leaf)) {
                return $null
            }
        }

        $manifest = Read-NormalizedPayloadManifest -Path $manifestPath
        if ($null -eq $manifest) {
            return $null
        }

        if ([string]$manifest.Fingerprint -ne $fingerprint) {
            return $null
        }

    Clear-StaleNormalizedVulnColumnCache -BasePath $BasePath -KeepPaths @($columnDirectoryPath, $manifestPath)
    return [PSCustomObject]@{
        Fingerprint = $fingerprint
        ColumnDirectoryPath = $columnDirectoryPath
        ColumnPaths = $columnPaths
        ManifestPath = $manifestPath
        Manifest = $manifest
    }
}

function Publish-NormalizedVulnColumnCache {
        [CmdletBinding()]
        [OutputType([pscustomobject])]
        param(
            [Parameter(Mandatory = $true)]
            [string]$BasePath,

            [Parameter(Mandatory = $true)]
            [hashtable]$VulnColumnPaths,

            [Parameter(Mandatory = $true)]
            [int]$VulnCount,

            [Parameter(Mandatory = $true)]
            [object[]]$Dates,

            [Parameter(Mandatory = $false)]
            [object]$Quality,

            [Parameter(Mandatory = $false)]
            [switch]$SkipObservedWindowMerge,

            [Parameter(Mandatory = $false)]
            [int]$InventoryTupleCount = 0
        )

        $fingerprint = Get-NormalizedVulnColumnCacheFingerprint -BasePath $BasePath -SkipObservedWindowMerge:$SkipObservedWindowMerge
        if ([string]::IsNullOrWhiteSpace($fingerprint)) {
            return $null
        }

        $columnDirectoryPath = Get-NormalizedVulnColumnCacheDirectoryPath -BasePath $BasePath -Fingerprint $fingerprint -Create
        $manifestPath = Get-NormalizedVulnColumnCacheManifestPath -BasePath $BasePath -Fingerprint $fingerprint -Create
        $existingEntry = Get-NormalizedVulnColumnCacheEntry -BasePath $BasePath -SkipObservedWindowMerge:$SkipObservedWindowMerge
        if ($existingEntry -and ([string]$existingEntry.Fingerprint -eq $fingerprint)) {
            return $existingEntry
        }

        if (-not (Test-Path -LiteralPath $columnDirectoryPath -PathType Container)) {
            [void](New-Item -Path $columnDirectoryPath -ItemType Directory -Force)
        }

        $cacheColumnPaths = Get-NormalizedVulnColumnCacheColumnPaths -DirectoryPath $columnDirectoryPath
        foreach ($columnName in @($cacheColumnPaths.Keys)) {
            $sourcePath = [string]$VulnColumnPaths[$columnName]
            $destinationPath = [string]$cacheColumnPaths[$columnName]
            if ([string]::IsNullOrWhiteSpace($sourcePath) -or -not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
                return $null
            }

            Copy-Item -LiteralPath $sourcePath -Destination $destinationPath -Force
        }

        $manifest = [ordered]@{
            Version = 'dashboard-vuln-column-cache-v1'
            Fingerprint = $fingerprint
            GeneratedOnUtc = (Get-Date).ToUniversalTime().ToString('o')
            VulnCount = $VulnCount
            Dates = @($Dates)
            Quality = $Quality
            SkipObservedWindowMerge = ($SkipObservedWindowMerge -eq $true)
            InventoryTupleCount = $InventoryTupleCount
        }
        Write-NormalizedPayloadManifest -Path $manifestPath -Manifest $manifest | Out-Null

    Clear-StaleNormalizedVulnColumnCache -BasePath $BasePath -KeepPaths @($columnDirectoryPath, $manifestPath)
    return [PSCustomObject]@{
        Fingerprint = $fingerprint
        ColumnDirectoryPath = $columnDirectoryPath
        ColumnPaths = $cacheColumnPaths
        ManifestPath = $manifestPath
        Manifest = [PSCustomObject]$manifest
    }
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
    foreach ($file in @(Get-NvdCveFingerprintSourceFileSet -BasePath $BasePath)) {
        if ($null -ne $file) { $files.Add($file) }
    }

    if ($files.Count -eq 0) {
        return $null
    }

    return (Get-FileSetFingerprint -Version 'dashboard-payload-cache-v5' -Files @($files) -MetadataLines @(
            ('SkipObservedWindowMerge=' + ($SkipObservedWindowMerge -eq $true))
        ))
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

function Get-NormalizedPayloadSiblingManifestPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PayloadPath
    )

    $resolvedPayloadPath = [System.IO.Path]::GetFullPath($PayloadPath)
    if ($resolvedPayloadPath.EndsWith('.json.gz', [System.StringComparison]::OrdinalIgnoreCase)) {
        return ($resolvedPayloadPath.Substring(0, $resolvedPayloadPath.Length - '.gz'.Length))
    }

    return ($resolvedPayloadPath + '.json')
}

function Write-CombinedPayloadGzipFallback {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Lookups,

        [Parameter(Mandatory = $true)]
        [string]$VulnsPath,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $payload = [ordered]@{
        lookups = $Lookups
        vulnsFormat = 'rows-v1'
        vulns = (Get-Content -Path $VulnsPath -Raw | ConvertFrom-Json -Depth 20)
    }
    $json = $payload | ConvertTo-Json -Compress -Depth 100

    $fileStream = [System.IO.File]::Create($OutputPath)
    try {
        $gzip = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionLevel]::Fastest)
        try {
            $writer = [System.IO.StreamWriter]::new($gzip, [System.Text.UTF8Encoding]::new($false))
            try {
                $writer.Write($json)
            }
            finally {
                $writer.Dispose()
            }
        }
        finally {
            $gzip.Dispose()
        }
    }
    finally {
        $fileStream.Dispose()
    }
}

function Resolve-NormalizedPayloadManifestPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$PayloadPath,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$ManifestPath
    )

    if (-not [string]::IsNullOrWhiteSpace($ManifestPath)) {
        return [System.IO.Path]::GetFullPath($ManifestPath)
    }

    if (-not [string]::IsNullOrWhiteSpace($PayloadPath)) {
        return (Get-NormalizedPayloadSiblingManifestPath -PayloadPath $PayloadPath)
    }

    return $null
}

function ConvertTo-NormalizedPayloadManifestRecord {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        $Manifest
    )

    $record = [ordered]@{}
    if ($Manifest -is [System.Collections.IDictionary]) {
        foreach ($key in $Manifest.Keys) {
            $record[[string]$key] = $Manifest[$key]
        }
    }
    else {
        foreach ($property in $Manifest.PSObject.Properties) {
            $record[$property.Name] = $property.Value
        }
    }

    return $record
}

function Confirm-NormalizedPayloadManifestPayloadSha {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        $Manifest,

        [Parameter(Mandatory = $true)]
        [string]$PayloadPath,

        [Parameter(Mandatory = $false)]
        [switch]$ThrowOnMismatch
    )

    $manifestRecord = ConvertTo-NormalizedPayloadManifestRecord -Manifest $Manifest
    $actualPayloadSha256 = Get-FileSha256Hex -Path $PayloadPath
    $manifestPayloadSha256 = if ($manifestRecord.Contains('PayloadSha256')) { [string]$manifestRecord.PayloadSha256 } else { '' }

    if (
        -not [string]::IsNullOrWhiteSpace($manifestPayloadSha256) -and
        -not [System.StringComparer]::OrdinalIgnoreCase.Equals($manifestPayloadSha256, $actualPayloadSha256)
    ) {
        $message = "Normalized payload hash mismatch for '$PayloadPath'. Manifest has '$manifestPayloadSha256' but file is '$actualPayloadSha256'."
        if ($ThrowOnMismatch) {
            throw $message
        }

        Write-Warning $message
        return $null
    }

    $manifestRecord.PayloadSha256 = $actualPayloadSha256
    return $manifestRecord
}

function Export-NormalizedPayloadArtifacts {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Internal helper optionally writes both payload and manifest outputs as one operation.')]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PayloadPath,

        [Parameter(Mandatory = $true)]
        $PayloadManifest,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$OutputPayloadPath,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$OutputManifestPath
    )

    $resolvedOutputPayloadPath = if (-not [string]::IsNullOrWhiteSpace($OutputPayloadPath)) { [System.IO.Path]::GetFullPath($OutputPayloadPath) } else { $null }
    $resolvedOutputManifestPath = Resolve-NormalizedPayloadManifestPath -PayloadPath $resolvedOutputPayloadPath -ManifestPath $OutputManifestPath

    if (-not [string]::IsNullOrWhiteSpace($resolvedOutputPayloadPath)) {
        $payloadDirectory = Split-Path -Path $resolvedOutputPayloadPath -Parent
        if (-not [string]::IsNullOrWhiteSpace($payloadDirectory) -and -not (Test-Path -LiteralPath $payloadDirectory -PathType Container)) {
            [void](New-Item -Path $payloadDirectory -ItemType Directory -Force)
        }

        Copy-Item -LiteralPath $PayloadPath -Destination $resolvedOutputPayloadPath -Force
    }

    if (-not [string]::IsNullOrWhiteSpace($resolvedOutputManifestPath)) {
        Write-NormalizedPayloadManifest -Path $resolvedOutputManifestPath -Manifest $PayloadManifest | Out-Null
    }

    return [PSCustomObject]@{
        PayloadPath = $resolvedOutputPayloadPath
        ManifestPath = $resolvedOutputManifestPath
    }
}

function Read-NormalizedPayloadManifest {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }

    return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -Depth 30)
}

function Write-NormalizedPayloadManifest {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        $Manifest
    )

    $resolvedPath = [System.IO.Path]::GetFullPath($Path)
    $directoryPath = Split-Path -Path $resolvedPath -Parent
    if (-not [string]::IsNullOrWhiteSpace($directoryPath) -and -not (Test-Path -LiteralPath $directoryPath -PathType Container)) {
        [void](New-Item -Path $directoryPath -ItemType Directory -Force)
    }

    $tempPath = Join-Path $directoryPath ('.tmp-' + [System.Guid]::NewGuid().ToString('N') + '.json')
    [System.IO.File]::WriteAllText($tempPath, ($Manifest | ConvertTo-Json -Compress -Depth 30), [System.Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $tempPath -Destination $resolvedPath -Force
    return $resolvedPath
}

function Get-DashboardSemanticValidationLogicVersion {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    return 'streaming-large-dataset-v3'
}

function Set-NormalizedPayloadSemanticValidationAttestation {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal helper only rewrites a local cache manifest during scripted validation flow.')]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ManifestPath,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedFingerprint,

        [Parameter(Mandatory = $true)]
        $Attestation
    )

    $manifest = Read-NormalizedPayloadManifest -Path $ManifestPath
    if ($null -eq $manifest) {
        return $null
    }

    if ([string]$manifest.Fingerprint -ne $ExpectedFingerprint) {
        return $null
    }

    $manifestRecord = [ordered]@{}
    foreach ($property in $manifest.PSObject.Properties) {
        $manifestRecord[$property.Name] = $property.Value
    }

    $manifestRecord.SemanticValidationAttestation = $Attestation
    Write-NormalizedPayloadManifest -Path $ManifestPath -Manifest $manifestRecord | Out-Null
    return ([pscustomobject]$manifestRecord)
}

function Get-DashboardValidationSidecarPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HtmlPath
    )

    return ([System.IO.Path]::GetFullPath($HtmlPath) + '.validation.json')
}

function Read-DashboardValidationSidecar {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HtmlPath
    )

    $sidecarPath = Get-DashboardValidationSidecarPath -HtmlPath $HtmlPath
    if (-not (Test-Path -LiteralPath $sidecarPath -PathType Leaf)) {
        return $null
    }

    return (Get-Content -LiteralPath $sidecarPath -Raw | ConvertFrom-Json -Depth 30)
}

function Write-DashboardValidationSidecar {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HtmlPath,

        [Parameter(Mandatory = $true)]
        $PayloadManifest,

        [Parameter(Mandatory = $true)]
        [string]$DashboardPayloadSha256,

        [Parameter(Mandatory = $true)]
        [int]$DashboardPayloadRowCount
    )

    $resolvedHtmlPath = [System.IO.Path]::GetFullPath($HtmlPath)
    $sidecarPath = Get-DashboardValidationSidecarPath -HtmlPath $resolvedHtmlPath
    $payloadSha256 = if ($PayloadManifest.PSObject.Properties['PayloadSha256'] -and -not [string]::IsNullOrWhiteSpace([string]$PayloadManifest.PayloadSha256)) {
        [string]$PayloadManifest.PayloadSha256
    }
    else {
        $null
    }

    $sidecar = [ordered]@{
        Version = 'dashboard-validation-sidecar-v1'
        HtmlPath = $resolvedHtmlPath
        GeneratedOnUtc = (Get-Date).ToUniversalTime().ToString('o')
        SourceFingerprint = [string]$PayloadManifest.Fingerprint
        PayloadSha256 = $payloadSha256
        PayloadRowCount = [int]$PayloadManifest.VulnCount
        DeviceCount = [int]$PayloadManifest.DeviceCount
        CveCount = [int]$PayloadManifest.CveCount
        Quality = $PayloadManifest.Quality
        SourceMetadata = if ($PayloadManifest.PSObject.Properties['SourceMetadata']) { $PayloadManifest.SourceMetadata } else { $null }
        SkipObservedWindowMerge = [bool]($PayloadManifest.PSObject.Properties['SkipObservedWindowMerge'] -and $PayloadManifest.SkipObservedWindowMerge)
        DashboardPayloadSha256 = $DashboardPayloadSha256
        DashboardPayloadRowCount = $DashboardPayloadRowCount
        DashboardPayloadMatchesNormalizedPayload = (($DashboardPayloadSha256 -eq $payloadSha256) -and ($DashboardPayloadRowCount -eq [int]$PayloadManifest.VulnCount))
        SemanticValidationAttestation = if ($PayloadManifest.PSObject.Properties['SemanticValidationAttestation']) { $PayloadManifest.SemanticValidationAttestation } else { $null }
    }

    Write-NormalizedPayloadManifest -Path $sidecarPath -Manifest $sidecar | Out-Null
    return $sidecarPath
}

function Set-DashboardValidationSidecarSemanticAttestation {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal helper only rewrites a local validation sidecar during scripted validation flow.')]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HtmlPath,

        [Parameter(Mandatory = $true)]
        $Attestation
    )

    $sidecarPath = Get-DashboardValidationSidecarPath -HtmlPath $HtmlPath
    $sidecar = Read-DashboardValidationSidecar -HtmlPath $HtmlPath
    if ($null -eq $sidecar) {
        return $null
    }

    $sidecarRecord = [ordered]@{}
    foreach ($property in $sidecar.PSObject.Properties) {
        $sidecarRecord[$property.Name] = $property.Value
    }

    $sidecarRecord.SemanticValidationAttestation = $Attestation
    Write-NormalizedPayloadManifest -Path $sidecarPath -Manifest $sidecarRecord | Out-Null
    return ([pscustomobject]$sidecarRecord)
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

    $manifest = Read-NormalizedPayloadManifest -Path $manifestPath
    if ([string]$manifest.Fingerprint -ne $fingerprint) {
        return $null
    }

    $manifestRecord = Confirm-NormalizedPayloadManifestPayloadSha -Manifest $manifest -PayloadPath $payloadPath
    if ($null -eq $manifestRecord) {
        return $null
    }

    $manifest = [PSCustomObject]$manifestRecord

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
        [object]$SourceMetadata,

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
    $payloadSha256 = Get-FileSha256Hex -Path $PayloadPath

    Copy-Item -LiteralPath $PayloadPath -Destination $tempPayloadPath -Force
    $manifest = [ordered]@{
        Version = 'dashboard-payload-cache-v6'
        Fingerprint = $fingerprint
        GeneratedOnUtc = (Get-Date).ToUniversalTime().ToString('o')
        PayloadSha256 = $payloadSha256
        VulnCount = $VulnCount
        DeviceCount = $DeviceCount
        CveCount = $CveCount
        Quality = $Quality
        SourceMetadata = $SourceMetadata
        SkipObservedWindowMerge = ($SkipObservedWindowMerge -eq $true)
        SemanticValidationAttestation = $null
    }
    Write-NormalizedPayloadManifest -Path $cacheManifestPath -Manifest $manifest | Out-Null

    Move-Item -LiteralPath $tempPayloadPath -Destination $cachePayloadPath -Force
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
    $key = if ($value -is [string]) { $value } else { $value.ToString() }
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

    $severityIndexByName = @{
        Critical = 0
        High = 1
        Medium = 2
        Low = 3
        None = 4
    }

    return [PSCustomObject]@{
        Lookups = @{
            vendors = [System.Collections.Generic.List[string]]::new()
            severities = @('Critical', 'High', 'Medium', 'Low', 'None')
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
            inventory = [System.Collections.Generic.List[PSObject]]::new()
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
            inventory = Get-CaseSensitiveIndexMap
        }
        DateValueCache = @{}
        Machines = @{}
        AdvancedHuntingData = @{}
        AdvancedHuntingDeviceUsers = @{}
        AdvancedHuntingInventoryData = @{}
        NvdCveData = @{}
        SeverityIndexByName = $severityIndexByName
        HasNoTags = $false
    }
}

function ConvertTo-NormalizedLookupRecord {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Lookups,

        [Parameter(Mandatory = $true)]
        [int]$NoTagsIdx
    )

    return [PSCustomObject]@{
        vendors = $Lookups.vendors
        severities = $Lookups.severities
        exploitLevels = $Lookups.exploitLevels
        groups = $Lookups.groups
        platforms = $Lookups.platforms
        tags = $Lookups.tags
        updates = $Lookups.updates
        versions = $Lookups.versions
        dates = $Lookups.dates
        diskPaths = $Lookups.diskPaths
        regPaths = $Lookups.regPaths
        affSoftware = $Lookups.affSoftware
        batchTitles = $Lookups.batchTitles
        devices = $Lookups.devices
        inventory = $Lookups.inventory
        software = $Lookups.software
        cves = $Lookups.cves
        noTagsIdx = $NoTagsIdx
    }
}

function Restore-ContentStoreNormalizedLookupsFromColumnCache {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DataPath,

        [Parameter(Mandatory = $true)]
        [hashtable]$Machines,

        [Parameter(Mandatory = $false)]
        [hashtable]$AdvancedHuntingData = @{},

        [Parameter(Mandatory = $false)]
        [hashtable]$AdvancedHuntingDeviceUsers = @{},

        [Parameter(Mandatory = $false)]
        [hashtable]$AdvancedHuntingInventoryData = @{},

        [Parameter(Mandatory = $false)]
        [hashtable]$NvdCveData = @{},

        [Parameter(Mandatory = $false)]
        [object[]]$CachedDates = @()
    )

    $dictionaryPath = Get-VulnContentDictionaryPath -BasePath $DataPath
    if (-not (Test-Path -LiteralPath $dictionaryPath -PathType Leaf)) {
        throw "Content dictionary '$dictionaryPath' was not found."
    }

    Compress-NormalizationMachineLookup -Machines $Machines | Out-Null

    $context = Get-NormalizationContext
    $context.Machines = $Machines
    $context.AdvancedHuntingData = $AdvancedHuntingData
    $context.AdvancedHuntingDeviceUsers = $AdvancedHuntingDeviceUsers
    $context.AdvancedHuntingInventoryData = $AdvancedHuntingInventoryData
    $context.NvdCveData = $NvdCveData

    foreach ($cachedDate in @($CachedDates)) {
        $dateText = [string]$cachedDate
        if ([string]::IsNullOrWhiteSpace($dateText)) {
            continue
        }

        if (-not $context.Indexes.dates.ContainsKey($dateText)) {
            $context.Indexes.dates[$dateText] = $context.Lookups.dates.Count
            $context.Lookups.dates.Add($dateText)
        }
    }

    foreach ($deviceProfile in @(Read-VulnContentDictionaryArrayEntries -Path $dictionaryPath -PropertyName 'deviceProfiles')) {
        Add-NormalizedDevice `
            -DeviceId ([string](Get-VulnPropertyValue -InputObject $deviceProfile -Name 'id')) `
            -DeviceName ([string](Get-VulnPropertyValue -InputObject $deviceProfile -Name 'n')) `
            -GroupName ([string](Get-VulnPropertyValue -InputObject $deviceProfile -Name 'g')) `
            -OsPlatform ([string](Get-VulnPropertyValue -InputObject $deviceProfile -Name 'o')) `
            -OsVersion ([string](Get-VulnPropertyValue -InputObject $deviceProfile -Name 'ov')) `
            -MachineTags @(Get-StringArray -Value (Get-VulnPropertyValue -InputObject $deviceProfile -Name 't')) `
            -Context $context | Out-Null
    }

    foreach ($contentTemplate in @(Read-VulnContentDictionaryArrayEntries -Path $dictionaryPath -PropertyName 'contentTemplates')) {
        Resolve-NormalizedContentLookup `
            -SoftwareVendor ([string](Get-VulnPropertyValue -InputObject $contentTemplate -Name 'sv')) `
            -SoftwareName ([string](Get-VulnPropertyValue -InputObject $contentTemplate -Name 'sn')) `
            -RecommendationReference ([string](Get-VulnPropertyValue -InputObject $contentTemplate -Name 'rr')) `
            -CveId ([string](Get-VulnPropertyValue -InputObject $contentTemplate -Name 'c')) `
            -CvssScore (Get-VulnPropertyValue -InputObject $contentTemplate -Name 'sc') `
            -SeverityLevel ([string](Get-VulnPropertyValue -InputObject $contentTemplate -Name 'sev')) `
            -ExploitabilityLevel ([string](Get-VulnPropertyValue -InputObject $contentTemplate -Name 'ex')) `
            -CveUrl ([string](Get-VulnPropertyValue -InputObject $contentTemplate -Name 'bu')) `
            -CveBatchTitle ([string](Get-VulnPropertyValue -InputObject $contentTemplate -Name 'bt')) `
            -RecommendedSecurityUpdate ([string](Get-VulnPropertyValue -InputObject $contentTemplate -Name 'ru')) `
            -RecommendedSecurityUpdateId ([string](Get-VulnPropertyValue -InputObject $contentTemplate -Name 'rid')) `
            -RecommendedSecurityUpdateUrl ([string](Get-VulnPropertyValue -InputObject $contentTemplate -Name 'url')) `
            -SoftwareVersion ([string](Get-VulnPropertyValue -InputObject $contentTemplate -Name 'ver')) `
            -DiskPaths @(Get-StringArray -Value (Get-VulnPropertyValue -InputObject $contentTemplate -Name 'dp')) `
            -RegistryPaths @(Get-StringArray -Value (Get-VulnPropertyValue -InputObject $contentTemplate -Name 'rp')) `
            -SecurityUpdateAvailable ((Get-VulnPropertyValue -InputObject $contentTemplate -Name 'ua') -eq $true) `
            -Context $context | Out-Null
    }

    $lookups = $context.Lookups
    $tagIndex = $context.Indexes.tags
    $noTagsLabel = '(No Tags)'
    if ($context.HasNoTags -and -not $tagIndex.ContainsKey($noTagsLabel)) {
        $tagIndex[$noTagsLabel] = $lookups.tags.Count
        $lookups.tags.Add($noTagsLabel)
    }
    $noTagsIdx = if ($tagIndex.ContainsKey($noTagsLabel)) { $tagIndex[$noTagsLabel] } else { -1 }

    Update-NormalizedAffectedSoftwareLookup -Lookups $lookups

    return [PSCustomObject]@{
        Lookups = (ConvertTo-NormalizedLookupRecord -Lookups $lookups -NoTagsIdx $noTagsIdx)
        Quality = [PSCustomObject]@{
            FirstLastSwappedCount = 0
        }
        Context = $context
    }
}

function Restore-NormalizedVulnColumnPathsFromCache {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$CachedColumnPaths,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$RestoredLookupsResult,

        [Parameter(Mandatory = $true)]
        [string]$OutputDirectoryPath,

        [Parameter(Mandatory = $false)]
        [int]$CachedInventoryTupleCount = 0
    )

    $context = $RestoredLookupsResult.Context
    $currentInventoryTupleCount = if ($null -ne $context -and $null -ne $context.AdvancedHuntingInventoryData) { $context.AdvancedHuntingInventoryData.Count } else { 0 }
    if (($CachedInventoryTupleCount -eq 0) -and ($currentInventoryTupleCount -eq 0)) {
        return [PSCustomObject]@{
            ColumnPaths = $CachedColumnPaths
            RefreshedInventoryColumn = $false
            RowCount = 0
        }
    }

    if ($null -eq $context) {
        throw 'Restored lookup result does not contain the normalization context needed to refresh cached inventory columns.'
    }

    $resolvedOutputDirectoryPath = [System.IO.Path]::GetFullPath($OutputDirectoryPath)
    if (Test-Path -LiteralPath $resolvedOutputDirectoryPath -PathType Container) {
        Remove-Item -LiteralPath $resolvedOutputDirectoryPath -Recurse -Force -ErrorAction SilentlyContinue
    }
    [void](New-Item -Path $resolvedOutputDirectoryPath -ItemType Directory -Force)

    $inventoryColumnPath = Join-Path $resolvedOutputDirectoryPath 'iv.json'
    $inventoryColumnWriter = [PSCustomObject]@{
        Path = $inventoryColumnPath
        StreamWriter = [System.IO.StreamWriter]::new($inventoryColumnPath, $false, [System.Text.UTF8Encoding]::new($false))
        Buffer = [System.Text.StringBuilder]::new(131072)
        HasValue = $false
    }
    $inventoryColumnWriter.StreamWriter.Write('[')

    $readerStates = [System.Collections.Generic.List[System.IDisposable]]::new()
    $deviceReaderState = $null
    $softwareReaderState = $null
    $versionReaderState = $null

    try {
        foreach ($requiredColumnName in @('d', 's', 'v')) {
            $columnPath = [string]$CachedColumnPaths[$requiredColumnName]
            if ([string]::IsNullOrWhiteSpace($columnPath) -or -not (Test-Path -LiteralPath $columnPath -PathType Leaf)) {
                throw "Cached normalized vulnerability column '$requiredColumnName' was not found."
            }
        }

        $deviceReaderState = Open-CompactJsonArrayReader -Path ([string]$CachedColumnPaths['d'])
        $softwareReaderState = Open-CompactJsonArrayReader -Path ([string]$CachedColumnPaths['s'])
        $versionReaderState = Open-CompactJsonArrayReader -Path ([string]$CachedColumnPaths['v'])
        [void]$readerStates.Add($deviceReaderState.JsonReader)
        [void]$readerStates.Add($deviceReaderState.StreamReader)
        [void]$readerStates.Add($softwareReaderState.JsonReader)
        [void]$readerStates.Add($softwareReaderState.StreamReader)
        [void]$readerStates.Add($versionReaderState.JsonReader)
        [void]$readerStates.Add($versionReaderState.StreamReader)

        $lookups = $context.Lookups
        $rowCount = 0
        while ($true) {
            $deviceValueState = Read-NextCompactJsonArrayValue -ReaderState $deviceReaderState
            $softwareValueState = Read-NextCompactJsonArrayValue -ReaderState $softwareReaderState
            $versionValueState = Read-NextCompactJsonArrayValue -ReaderState $versionReaderState

            if ((-not $deviceValueState.HasValue) -and (-not $softwareValueState.HasValue) -and (-not $versionValueState.HasValue)) {
                break
            }

            if ((-not $deviceValueState.HasValue) -or (-not $softwareValueState.HasValue) -or (-not $versionValueState.HasValue)) {
                throw 'Cached normalized vulnerability columns d/s/v have mismatched lengths.'
            }

            $deviceId = $null
            $softwareVendor = ''
            $softwareName = ''
            $softwareVersion = ''

            if ($null -ne $deviceValueState.Value) {
                $deviceIndex = [int]$deviceValueState.Value
                if ($deviceIndex -ge 0 -and $deviceIndex -lt $lookups.devices.Count) {
                    $deviceEntry = $lookups.devices[$deviceIndex]
                    $deviceId = if ($deviceEntry.PSObject.Properties['id']) { [string]$deviceEntry.id } else { $null }
                }
            }

            if ($null -ne $softwareValueState.Value) {
                $softwareIndex = [int]$softwareValueState.Value
                if ($softwareIndex -ge 0 -and $softwareIndex -lt $lookups.software.Count) {
                    $softwareEntry = $lookups.software[$softwareIndex]
                    $softwareName = if ($softwareEntry.PSObject.Properties['n']) { [string]$softwareEntry.n } else { '' }
                    if ($softwareEntry.PSObject.Properties['v'] -and $null -ne $softwareEntry.v) {
                        $vendorIndex = [int]$softwareEntry.v
                        if ($vendorIndex -ge 0 -and $vendorIndex -lt $lookups.vendors.Count) {
                            $softwareVendor = [string]$lookups.vendors[$vendorIndex]
                        }
                    }
                }
            }

            if ($null -ne $versionValueState.Value) {
                $versionIndex = [int]$versionValueState.Value
                if ($versionIndex -ge 0 -and $versionIndex -lt $lookups.versions.Count) {
                    $softwareVersion = [string]$lookups.versions[$versionIndex]
                }
            }

            $inventoryValue = Resolve-NormalizedInventoryLookup `
                -DeviceId $deviceId `
                -SoftwareVendor $softwareVendor `
                -SoftwareName $softwareName `
                -SoftwareVersion $softwareVersion `
                -Context $context
            Write-CompactColumnFileValue -WriterState $inventoryColumnWriter -Value $inventoryValue

            $rowCount++
            if (($rowCount % 100000) -eq 0) {
                if ($inventoryColumnWriter.Buffer.Length -gt 0) {
                    $inventoryColumnWriter.StreamWriter.Write($inventoryColumnWriter.Buffer.ToString())
                    [void]$inventoryColumnWriter.Buffer.Clear()
                }
                $inventoryColumnWriter.StreamWriter.Flush()
            }
        }
    }
    finally {
        foreach ($disposable in $readerStates) {
            $disposable.Dispose()
        }

        if ($inventoryColumnWriter.StreamWriter) {
            if ($inventoryColumnWriter.Buffer.Length -gt 0) {
                $inventoryColumnWriter.StreamWriter.Write($inventoryColumnWriter.Buffer.ToString())
                [void]$inventoryColumnWriter.Buffer.Clear()
            }
            $inventoryColumnWriter.StreamWriter.Write(']')
            $inventoryColumnWriter.StreamWriter.Dispose()
            $inventoryColumnWriter.StreamWriter = $null
        }
    }

    $restoredColumnPaths = [ordered]@{}
    foreach ($columnName in @('d', 'c', 's', 'v', 'f', 'l', 'ua', 'u', 'dp', 'rp', 'iv')) {
        $restoredColumnPaths[$columnName] = if ($columnName -eq 'iv') { $inventoryColumnPath } else { [string]$CachedColumnPaths[$columnName] }
    }

    return [PSCustomObject]@{
        ColumnPaths = $restoredColumnPaths
        RefreshedInventoryColumn = $true
        RowCount = $rowCount
    }
}

function Write-CompactVulnRecordJson {
    param(
        [Parameter(Mandatory = $true)]
        [Newtonsoft.Json.JsonTextWriter]$Writer,

        [Parameter(Mandatory = $true)]
        $Record
    )

    if ($null -eq $Record) { return }
    $Writer.WriteStartArray()
    foreach ($compactValue in $Record) {
        if ($null -eq $compactValue) {
            $Writer.WriteNull()
            continue
        }

        if ($compactValue -is [System.Collections.IEnumerable] -and $compactValue -isnot [string]) {
            $Writer.WriteStartArray()
            foreach ($nestedValue in $compactValue) {
                if ($null -eq $nestedValue) {
                    $Writer.WriteNull()
                }
                else {
                    $Writer.WriteValue($nestedValue)
                }
            }
            $Writer.WriteEndArray()
            continue
        }

        $Writer.WriteValue($compactValue)
    }
    $Writer.WriteEndArray()
}

function Resolve-UpdateLookupIndex {
    param(
        [AllowNull()][AllowEmptyString()][string]$UpdateName,
        [AllowNull()][AllowEmptyString()][string]$UpdateId,
        [AllowNull()][AllowEmptyString()][string]$UpdateUrl,
        [System.Collections.Generic.List[PSObject]]$UpdateList,
        [hashtable]$UpdateIndex
    )

    $name = if ($UpdateName -and $UpdateName -ne '--') { $UpdateName } else { $null }
    if ($null -eq $name -or $name -eq '') { return -1 }
    $key = @([string]$name, [string]$UpdateId, [string]$UpdateUrl) -join '|'
    if ($UpdateIndex.ContainsKey($key)) { return [int]$UpdateIndex[$key] }
    $idx = $UpdateList.Count
    $UpdateIndex[$key] = $idx
    $UpdateList.Add([PSCustomObject]@{ n = $name; id = $UpdateId; url = $UpdateUrl })
    return $idx
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

function Compress-NormalizationMachineLookup {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [hashtable]$Machines
    )

    if ($null -eq $Machines -or $Machines.Count -eq 0) {
        return @{}
    }

    foreach ($deviceId in @($Machines.Keys)) {
        $machine = $Machines[$deviceId]
        if ($null -eq $machine) {
            $Machines.Remove($deviceId)
            continue
        }

        $machineTuple = ConvertTo-NormalizationMachineTuple -Machine $machine
        if ($null -eq $machineTuple) {
            $Machines.Remove($deviceId)
            continue
        }

        $Machines[$deviceId] = $machineTuple
    }

    return $Machines
}

function Add-NormalizedDevice {
    param(
        $DeviceId,
        $DeviceName,
        $GroupName,
        $OsPlatform,
        $OsVersion,
        $MachineTags,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Context
    )

    $lookups = $Context.Lookups
    $deviceIndex = $Context.Indexes.devices
    $groupIndex = $Context.Indexes.groups
    $platformIndex = $Context.Indexes.platforms
    $tagIndex = $Context.Indexes.tags

    $deviceKey = if (-not [string]::IsNullOrWhiteSpace($DeviceId)) {
        $DeviceId
    }
    else {
        @(
            [string]$DeviceName
            [string]$GroupName
            [string]$OsPlatform
            [string]$OsVersion
        ) -join '|'
    }

    if (-not $deviceIndex.ContainsKey($deviceKey)) {
        $machine = if (-not [string]::IsNullOrWhiteSpace($DeviceId)) { $Context.Machines[$DeviceId] } else { $null }
        $machineTuple = if ($machine -is [System.Array] -and $machine.Length -ge 10) { $machine } else { $null }
        $machineOsVersion = if ($machineTuple -and $machineTuple.Length -ge 11) {
            [string]$machineTuple[10]
        }
        elseif ($machine -and -not $machineTuple) {
            [string]$machine.PSObject.Properties['osVersion']?.Value
        }
        else {
            $null
        }
        $machineDeviceName = if ($machineTuple -and $machineTuple.Length -ge 12) {
            [string]$machineTuple[11]
        }
        elseif ($machine -and -not $machineTuple) {
            [string]$machine.PSObject.Properties['computerDnsName']?.Value
        }
        else {
            $null
        }
        $machineGroupName = if ($machineTuple -and $machineTuple.Length -ge 13) {
            [string]$machineTuple[12]
        }
        elseif ($machine -and -not $machineTuple) {
            [string]$machine.PSObject.Properties['rbacGroupName']?.Value
        }
        else {
            $null
        }
        $machinePlatform = if ($machineTuple -and $machineTuple.Length -ge 14) {
            [string]$machineTuple[13]
        }
        elseif ($machine -and -not $machineTuple) {
            [string]$machine.PSObject.Properties['osPlatform']?.Value
        }
        else {
            $null
        }
        $machineResolvedTags = if ($machineTuple -and $machineTuple.Length -ge 15) {
            @($machineTuple[14])
        }
        elseif ($machine -and -not $machineTuple) {
            @(Get-NormalizedMachineTag -Tags $machine.PSObject.Properties['machineTags']?.Value)
        }
        else {
            @()
        }
        $machineUsers = [string[]]@()
        if ($null -ne $Context.AdvancedHuntingDeviceUsers -and -not [string]::IsNullOrWhiteSpace($DeviceId)) {
            $rawMachineUsers = $Context.AdvancedHuntingDeviceUsers[[string]$DeviceId]
            if ($null -ne $rawMachineUsers) {
                $machineUsers = [string[]]@($rawMachineUsers | ForEach-Object {
                    if (-not [string]::IsNullOrWhiteSpace([string]$_)) {
                        [string]$_
                    }
                })
            }
        }

        $resolvedGroupName = if ($null -ne $machine) { $machineGroupName } else { $GroupName }
        if ([string]::IsNullOrWhiteSpace([string]$resolvedGroupName)) {
            $resolvedGroupName = if ([string]::IsNullOrWhiteSpace([string]$GroupName)) { '(none)' } else { $GroupName }
        }
        $groupIdx = Get-OrCreateIndex -value $resolvedGroupName -list $lookups.groups -indexMap $groupIndex

        $osPlat = if (-not [string]::IsNullOrWhiteSpace([string]$machinePlatform)) { $machinePlatform } else { $OsPlatform }
        $platIdx = Get-OrCreateIndex -value $osPlat -list $lookups.platforms -indexMap $platformIndex

        $effectiveTags = if ($null -ne $machine -and @($machineResolvedTags).Count -gt 0) { @($machineResolvedTags) } elseif ($MachineTags) { @($MachineTags) } else { @() }
        $tagIndices = [System.Collections.Generic.List[int]]::new()
        foreach ($tag in $effectiveTags) {
            $tagIdx = Get-OrCreateIndex -value $tag -list $lookups.tags -indexMap $tagIndex
            if ($tagIdx -ge 0) { $tagIndices.Add($tagIdx) }
        }
        if ($tagIndices.Count -eq 0) { $Context.HasNoTags = $true }

        $deviceIndex[$deviceKey] = $lookups.devices.Count

        $machineInfo = $null
        if ($machine -or $machineUsers.Count -gt 0) {
            $machineLastSeen = if ($machineTuple) { $machineTuple[8] } elseif ($machine) { $machine.PSObject.Properties['lastSeen']?.Value } else { $null }
            $machineFirstSeen = if ($machineTuple) { $machineTuple[9] } elseif ($machine) { $machine.PSObject.Properties['firstSeen']?.Value } else { $null }
            $machineInfo = [PSCustomObject]@{
                ip = if ($machineTuple) { $machineTuple[0] } elseif ($machine) { $machine.PSObject.Properties['lastIpAddress']?.Value } else { $null }
                eip = if ($machineTuple) { $machineTuple[1] } elseif ($machine) { $machine.PSObject.Properties['lastExternalIpAddress']?.Value } else { $null }
                u = if ($machineUsers.Count -gt 0) { @($machineUsers) } else { $null }
                hs = if ($machineTuple) { $machineTuple[2] } elseif ($machine) { $machine.PSObject.Properties['healthStatus']?.Value } else { $null }
                rs = if ($machineTuple) { $machineTuple[3] } elseif ($machine) { $machine.PSObject.Properties['riskScore']?.Value } else { $null }
                el = if ($machineTuple) { $machineTuple[4] } elseif ($machine) { $machine.PSObject.Properties['exposureLevel']?.Value } else { $null }
                dv = if ($machineTuple) { $machineTuple[5] } elseif ($machine) { $machine.PSObject.Properties['deviceValue']?.Value } else { $null }
                mb = if ($machineTuple) { $machineTuple[6] } elseif ($machine) { $machine.PSObject.Properties['managedBy']?.Value } else { $null }
                aad = if ($machineTuple) { $machineTuple[7] } elseif ($machine) { $machine.PSObject.Properties['isAadJoined']?.Value } else { $null }
                ls = Get-NormalizationCachedYmdDate -Context $Context -DateValue $machineLastSeen
                fs = Get-NormalizationCachedYmdDate -Context $Context -DateValue $machineFirstSeen
            }
        }

        $lookups.devices.Add([PSCustomObject]@{
            id = $DeviceId
            n = if (-not [string]::IsNullOrWhiteSpace([string]$machineDeviceName)) { $machineDeviceName } elseif (-not [string]::IsNullOrWhiteSpace([string]$DeviceName)) { $DeviceName } else { '(no machine data)' }
            g = $groupIdx
            o = $platIdx
            ov = if (-not [string]::IsNullOrWhiteSpace([string]$machineOsVersion)) { $machineOsVersion } elseif (-not [string]::IsNullOrWhiteSpace([string]$OsVersion)) { $OsVersion } else { $null }
            t = $tagIndices
            m = $machineInfo
        })
    }

    return [int]$deviceIndex[$deviceKey]
}

function Add-NormalizedSoftware {
    param(
        $SoftwareVendor,
        $SoftwareName,
        $RecommendationReference,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Context
    )

    $lookups = $Context.Lookups
    $vendorIndex = $Context.Indexes.vendors
    $softwareIndex = $Context.Indexes.software

    $vendorIdx = Get-OrCreateIndex -value $SoftwareVendor -list $lookups.vendors -indexMap $vendorIndex

    $softwareKey = "$SoftwareVendor|$SoftwareName|$RecommendationReference"
    if (-not $softwareIndex.ContainsKey($softwareKey)) {
        $softwareIndex[$softwareKey] = $lookups.software.Count
        $lookups.software.Add([PSCustomObject]@{
            v = $vendorIdx
            n = $SoftwareName
            r = $RecommendationReference
        })
    }

    return [int]$softwareIndex[$softwareKey]
}

function Add-NormalizedCve {
    param(
        $CveId,
        $CvssScore,
        $SeverityLevel,
        $ExploitabilityLevel,
        $CveUrl,
        $CveBatchTitle,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Context
    )

    $lookups = $Context.Lookups
    $exploitIndex = $Context.Indexes.exploitLevels
    $cveIndex = $Context.Indexes.cves
    $affSoftwareIndex = $Context.Indexes.affSoftware
    $batchTitleIndex = $Context.Indexes.batchTitles
    $severityIndexByName = $Context.SeverityIndexByName

    $cveIdText = [string]$CveId
    $severityLevelText = [string]$SeverityLevel
    $exploitabilityLevelText = [string]$ExploitabilityLevel

    $cveKey = @(
        $cveIdText
        [string]$CvssScore
        $severityLevelText
        $exploitabilityLevelText
        [string]$CveUrl
        [string]$CveBatchTitle
    ) -join '|'

    if (-not $cveIndex.ContainsKey($cveKey)) {
        $sevIdx = if ($severityIndexByName.ContainsKey($severityLevelText)) {
            [int]$severityIndexByName[$severityLevelText]
        } else {
            -1
        }

        $expIdx = Get-OrCreateIndex -value $ExploitabilityLevel -list $lookups.exploitLevels -indexMap $exploitIndex
        $ahData = $Context.AdvancedHuntingData[$cveIdText]
        $nvdData = $Context.NvdCveData[$cveIdText]
        $publishedDate = $null
        $vulnDescription = $null
        $epssScore = $null
        $isExploitAvailable = $null
        $affSoftwareIndices = $null
        if ($ahData) {
            $publishedDate = $ahData.PublishedDate
            $vulnDescription = $ahData.VulnerabilityDescription
            $epssScore = $ahData.EpssScore
            if ($ahData.ContainsKey('IsExploitAvailable')) {
                $isExploitAvailable = $ahData.IsExploitAvailable
            }
            if ($ahData.AffectedSoftware -and @($ahData.AffectedSoftware).Count -gt 0) {
                $affSoftwareIndices = [System.Collections.Generic.List[int]]::new()
                foreach ($sw in @($ahData.AffectedSoftware)) {
                    $asIdx = Get-OrCreateIndex -value $sw -list $lookups.affSoftware -indexMap $affSoftwareIndex
                    if ($asIdx -ge 0) { $affSoftwareIndices.Add($asIdx) }
                }
            }
        }

        if ($nvdData) {
            if ([string]::IsNullOrWhiteSpace([string]$publishedDate)) {
                $publishedDate = $nvdData.PublishedDate
            }

            if ([string]::IsNullOrWhiteSpace([string]$vulnDescription)) {
                $vulnDescription = $nvdData.VulnerabilityDescription
            }
        }

        $btIdx = Get-OrCreateIndex -value $CveBatchTitle -list $lookups.batchTitles -indexMap $batchTitleIndex

        $cveIndex[$cveKey] = $lookups.cves.Count
        $lookups.cves.Add([PSCustomObject]@{
            id = $CveId
            sc = $CvssScore
            sv = $sevIdx
            ex = $expIdx
            u = $CveUrl
            bt = $btIdx
            pd = $publishedDate
            desc = $vulnDescription
            ep = $epssScore
            as = $affSoftwareIndices
            ea = $isExploitAvailable
            nlm = if ($nvdData) { $nvdData.LastModifiedDate } else { $null }
            nbs = if ($nvdData) { $nvdData.BaseScore } else { $null }
            nsv = if ($nvdData) { $nvdData.BaseSeverity } else { $null }
            nvec = if ($nvdData) { $nvdData.Vector } else { $null }
            nkev = if ($nvdData) { $nvdData.CisaExploitAdd } else { $null }
            ndu = if ($nvdData) { $nvdData.CisaActionDue } else { $null }
            nact = if ($nvdData) { $nvdData.CisaRequiredAction } else { $null }
            nw = if ($nvdData -and $nvdData.Weaknesses) { @($nvdData.Weaknesses) } else { $null }
        })
    }

    return [int]$cveIndex[$cveKey]
}

function Resolve-NormalizedLookupIndexList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object[]]$Values,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.IList]$List,

        [Parameter(Mandatory = $true)]
        [hashtable]$IndexMap
    )

    if ($null -eq $Values -or $Values.Count -eq 0) {
        return $null
    }

    $indices = [System.Collections.Generic.List[int]]::new()
    foreach ($value in $Values) {
        if ($null -eq $value) { continue }
        $index = Get-OrCreateIndex -value $value -list $List -indexMap $IndexMap
        if ($index -ge 0) {
            $indices.Add($index)
        }
    }

    if ($indices.Count -eq 0) {
        return $null
    }

    return ,([int[]]$indices.ToArray())
}

function Resolve-NormalizedInventoryLookup {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$DeviceId,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$SoftwareVendor,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$SoftwareName,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$SoftwareVersion,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$Context
    )

    $inventoryData = $Context.AdvancedHuntingInventoryData
    if ($null -eq $inventoryData -or $inventoryData.Count -eq 0) {
        return -1
    }

    $inventoryKey = Get-AdvancedHuntingInventoryMatchKey `
        -DeviceId ([string]$DeviceId) `
        -SoftwareVendor ([string]($SoftwareVendor ?? '')) `
        -SoftwareName ([string]($SoftwareName ?? '')) `
        -SoftwareVersion ([string]($SoftwareVersion ?? ''))
    if ([string]::IsNullOrWhiteSpace($inventoryKey)) {
        return -1
    }

    $inventoryRecord = $inventoryData[$inventoryKey]
    if ($null -eq $inventoryRecord) {
        return -1
    }

    $productCodeCpe = [string]$inventoryRecord.ProductCodeCpe
    $endOfSupportStatus = [string]$inventoryRecord.EndOfSupportStatus
    $endOfSupportDate = [string]$inventoryRecord.EndOfSupportDate
    if ([string]::IsNullOrWhiteSpace($productCodeCpe) -and [string]::IsNullOrWhiteSpace($endOfSupportStatus) -and [string]::IsNullOrWhiteSpace($endOfSupportDate)) {
        return -1
    }

    $lookups = $Context.Lookups
    $inventoryIndex = $Context.Indexes.inventory
    $lookupKey = @(
        [string]($productCodeCpe ?? '')
        [string]($endOfSupportStatus ?? '')
        [string]($endOfSupportDate ?? '')
    ) -join '|'

    if (-not $inventoryIndex.ContainsKey($lookupKey)) {
        $inventoryIndex[$lookupKey] = $lookups.inventory.Count
        $lookups.inventory.Add([PSCustomObject]@{
            cpe = if ([string]::IsNullOrWhiteSpace($productCodeCpe)) { $null } else { $productCodeCpe }
            eos = if ([string]::IsNullOrWhiteSpace($endOfSupportStatus)) { $null } else { $endOfSupportStatus }
            eod = if ([string]::IsNullOrWhiteSpace($endOfSupportDate)) { $null } else { $endOfSupportDate }
        })
    }

    return [int]$inventoryIndex[$lookupKey]
}

function Resolve-NormalizedSeenWindowIndexSet {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Context,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$FirstSeenValue,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$LastSeenValue,

        [Parameter(Mandatory = $false)]
        [ref]$FirstLastSwappedCount = ([ref]0)
    )

    $lookups = $Context.Lookups
    $dateIndex = $Context.Indexes.dates
    $firstSeen = Get-NormalizationCachedYmdDate -Context $Context -DateValue $FirstSeenValue
    $lastSeen = Get-NormalizationCachedYmdDate -Context $Context -DateValue $LastSeenValue

    if ($firstSeen -and $lastSeen -and $firstSeen -gt $lastSeen) {
        $temp = $firstSeen
        $firstSeen = $lastSeen
        $lastSeen = $temp
        $FirstLastSwappedCount.Value++
    }

    if (-not $firstSeen) { $firstSeen = '' }
    if (-not $lastSeen) { $lastSeen = '' }

    return [PSCustomObject]@{
        FirstSeenText = $firstSeen
        LastSeenText = $lastSeen
        FirstSeenIndex = (Get-OrCreateIndex -value $firstSeen -list $lookups.dates -indexMap $dateIndex)
        LastSeenIndex = (Get-OrCreateIndex -value $lastSeen -list $lookups.dates -indexMap $dateIndex)
    }
}

function Resolve-NormalizedContentLookup {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$SoftwareVendor,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$SoftwareName,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$RecommendationReference,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$CveId,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$CvssScore,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$SeverityLevel,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$ExploitabilityLevel,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$CveUrl,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$CveBatchTitle,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$RecommendedSecurityUpdate,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$RecommendedSecurityUpdateId,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$RecommendedSecurityUpdateUrl,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$SoftwareVersion,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object[]]$DiskPaths,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object[]]$RegistryPaths,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$SecurityUpdateAvailable,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$Context
    )

    $lookups = $Context.Lookups
    $indexes = $Context.Indexes

    $swIdx = Add-NormalizedSoftware `
        -SoftwareVendor ([string]($SoftwareVendor ?? '')) `
        -SoftwareName ([string]($SoftwareName ?? '')) `
        -RecommendationReference ([string]($RecommendationReference ?? '')) `
        -Context $Context

    $cveIdx = Add-NormalizedCve `
        -CveId $CveId `
        -CvssScore $CvssScore `
        -SeverityLevel $SeverityLevel `
        -ExploitabilityLevel $ExploitabilityLevel `
        -CveUrl (Convert-CveUrl -Url $CveUrl) `
        -CveBatchTitle $CveBatchTitle `
        -Context $Context

    $updIdx = Resolve-UpdateLookupIndex `
        -UpdateName ([string]$RecommendedSecurityUpdate) `
        -UpdateId ([string]$RecommendedSecurityUpdateId) `
        -UpdateUrl ([string]$RecommendedSecurityUpdateUrl) `
        -UpdateList $lookups.updates `
        -UpdateIndex $indexes.updates

    return [PSCustomObject]@{
        sw = $swIdx
        cve = $cveIdx
        ver = (Get-OrCreateIndex -value $SoftwareVersion -list $lookups.versions -indexMap $indexes.versions)
        upd = $updIdx
        ua = [int]($SecurityUpdateAvailable -eq $true)
        dp = Resolve-NormalizedLookupIndexList -Values $DiskPaths -List $lookups.diskPaths -IndexMap $indexes.diskPaths
        rp = Resolve-NormalizedLookupIndexList -Values $RegistryPaths -List $lookups.regPaths -IndexMap $indexes.regPaths
    }
}

function Get-NormalizedRecordLookup {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$DeviceId,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$DeviceName,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$GroupName,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$OsPlatform,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$OsVersion,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object[]]$MachineTags,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$SoftwareVendor,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$SoftwareName,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$RecommendationReference,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$CveId,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$CvssScore,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$SeverityLevel,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$ExploitabilityLevel,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$CveUrl,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$CveBatchTitle,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$RecommendedSecurityUpdate,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$RecommendedSecurityUpdateId,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$RecommendedSecurityUpdateUrl,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$SoftwareVersion,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object[]]$DiskPaths,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object[]]$RegistryPaths,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$SecurityUpdateAvailable,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$Context
    )

    $contentLookup = Resolve-NormalizedContentLookup `
        -SoftwareVendor ($SoftwareVendor ?? '') `
        -SoftwareName ($SoftwareName ?? '') `
        -RecommendationReference ($RecommendationReference ?? '') `
        -CveId $CveId `
        -CvssScore $CvssScore `
        -SeverityLevel $SeverityLevel `
        -ExploitabilityLevel $ExploitabilityLevel `
        -CveUrl $CveUrl `
        -CveBatchTitle $CveBatchTitle `
        -RecommendedSecurityUpdate $RecommendedSecurityUpdate `
        -RecommendedSecurityUpdateId $RecommendedSecurityUpdateId `
        -RecommendedSecurityUpdateUrl $RecommendedSecurityUpdateUrl `
        -SoftwareVersion $SoftwareVersion `
        -DiskPaths $DiskPaths `
        -RegistryPaths $RegistryPaths `
        -SecurityUpdateAvailable $SecurityUpdateAvailable `
        -Context $Context

    $inventoryLookup = Resolve-NormalizedInventoryLookup `
        -DeviceId $DeviceId `
        -SoftwareVendor $SoftwareVendor `
        -SoftwareName $SoftwareName `
        -SoftwareVersion $SoftwareVersion `
        -Context $Context

    $contentLookup = [PSCustomObject]@{
        sw = $contentLookup.sw
        cve = $contentLookup.cve
        ver = $contentLookup.ver
        upd = $contentLookup.upd
        ua = $contentLookup.ua
        dp = $contentLookup.dp
        rp = $contentLookup.rp
        inv = $inventoryLookup
    }

    return [PSCustomObject]@{
        DeviceIndex = Add-NormalizedDevice `
            -DeviceId ([string]$DeviceId) `
            -DeviceName $DeviceName `
            -GroupName $GroupName `
            -OsPlatform $OsPlatform `
            -OsVersion $OsVersion `
            -MachineTags $MachineTags `
            -Context $Context

        ContentLookup = $contentLookup
    }
}

function Write-NormalizedCompactRecordFromLookup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$WriterState,

        [Parameter(Mandatory = $true)]
        [object[]]$Record,

        [Parameter(Mandatory = $true)]
        [int]$DeviceIndex,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$ContentLookup,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$Context,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$FirstSeenValue,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$LastSeenValue,

        [Parameter(Mandatory = $false)]
        [ref]$FirstLastSwappedCount = ([ref]0)
    )

    $windowIndexSet = Resolve-NormalizedSeenWindowIndexSet `
        -Context $Context `
        -FirstSeenValue $FirstSeenValue `
        -LastSeenValue $LastSeenValue `
        -FirstLastSwappedCount $FirstLastSwappedCount

    [void](Set-NormalizedCompactRecordValues `
        -Record $Record `
        -DeviceIndex $DeviceIndex `
        -ContentLookup $ContentLookup `
        -FirstSeenIndex $windowIndexSet.FirstSeenIndex `
        -LastSeenIndex $windowIndexSet.LastSeenIndex)

    Write-NormalizedCompactRecord -WriterState $WriterState -Record $Record
}

function Write-NormalizedSourceRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$WriterState,

        [Parameter(Mandatory = $true)]
        [object[]]$Record,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$Context,

        [Parameter(Mandatory = $true)]
        [ref]$ProcessedCount,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$FirstSeenValue,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$LastSeenValue,

        [Parameter(Mandatory = $false)]
        [ref]$FirstLastSwappedCount = ([ref]0),

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$DeviceId,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$DeviceName,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$GroupName,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$OsPlatform,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$OsVersion,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object[]]$MachineTags,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$SoftwareVendor,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$SoftwareName,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$RecommendationReference,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$CveId,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$CvssScore,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$SeverityLevel,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$ExploitabilityLevel,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$CveUrl,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$CveBatchTitle,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$RecommendedSecurityUpdate,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$RecommendedSecurityUpdateId,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$RecommendedSecurityUpdateUrl,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$SoftwareVersion,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object[]]$DiskPaths,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object[]]$RegistryPaths,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$SecurityUpdateAvailable
    )

    $recordLookup = Get-NormalizedRecordLookup `
        -DeviceId ([string]$DeviceId) `
        -DeviceName $DeviceName `
        -GroupName $GroupName `
        -OsPlatform $OsPlatform `
        -OsVersion $OsVersion `
        -MachineTags $MachineTags `
        -SoftwareVendor $SoftwareVendor `
        -SoftwareName $SoftwareName `
        -RecommendationReference $RecommendationReference `
        -CveId $CveId `
        -CvssScore $CvssScore `
        -SeverityLevel $SeverityLevel `
        -ExploitabilityLevel $ExploitabilityLevel `
        -CveUrl $CveUrl `
        -CveBatchTitle $CveBatchTitle `
        -RecommendedSecurityUpdate $RecommendedSecurityUpdate `
        -RecommendedSecurityUpdateId $RecommendedSecurityUpdateId `
        -RecommendedSecurityUpdateUrl $RecommendedSecurityUpdateUrl `
        -SoftwareVersion $SoftwareVersion `
        -DiskPaths $DiskPaths `
        -RegistryPaths $RegistryPaths `
        -SecurityUpdateAvailable $SecurityUpdateAvailable `
        -Context $Context

    $ProcessedCount.Value++

    Write-NormalizedCompactRecordFromLookup `
        -WriterState $WriterState `
        -Record $Record `
        -DeviceIndex $recordLookup.DeviceIndex `
        -ContentLookup $recordLookup.ContentLookup `
        -Context $Context `
        -FirstSeenValue $FirstSeenValue `
        -LastSeenValue $LastSeenValue `
        -FirstLastSwappedCount $FirstLastSwappedCount

    if (($ProcessedCount.Value % 50000) -eq 0) {
        Write-Information ("  Processed {0} onboarded vulnerability record(s)..." -f $ProcessedCount.Value) -InformationAction Continue
    }

    if (($ProcessedCount.Value % 100000) -eq 0) {
        Sync-NormalizedVulnWriter -WriterState $WriterState
        Invoke-FullGarbageCollection
    }
}

function Set-NormalizedCompactRecordValues {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Record,

        [Parameter(Mandatory = $true)]
        [int]$DeviceIndex,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$ContentLookup,

        [Parameter(Mandatory = $true)]
        [int]$FirstSeenIndex,

        [Parameter(Mandatory = $true)]
        [int]$LastSeenIndex
    )

    $Record[0] = $DeviceIndex
    $Record[1] = $ContentLookup.cve
    $Record[2] = $ContentLookup.sw
    $Record[3] = $ContentLookup.ver
    $Record[4] = $FirstSeenIndex
    $Record[5] = $LastSeenIndex
    $Record[6] = $ContentLookup.ua
    $Record[7] = $ContentLookup.upd
    $Record[8] = $ContentLookup.dp
    $Record[9] = $ContentLookup.rp
    $Record[10] = $ContentLookup.inv
    return $Record
}

function Test-NormalizedWriterRowCount {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$WriterCloseResult,

        [Parameter(Mandatory = $true)]
        [int]$ExpectedRowCount
    )

    switch ($WriterCloseResult.Mode) {
        'rows' {
            if ($WriterCloseResult.VulnsPath -and (Test-Path -LiteralPath $WriterCloseResult.VulnsPath -PathType Leaf)) {
                $actualRowCount = Get-CompactVulnJsonRowCount -Path $WriterCloseResult.VulnsPath
                if ($actualRowCount -ne $ExpectedRowCount) {
                    throw ("Normalized vulnerability payload row count mismatch after streaming write. Expected {0}, found {1} in '{2}'." -f $ExpectedRowCount, $actualRowCount, $WriterCloseResult.VulnsPath)
                }
            }
        }
        'payload' {
            if ($WriterCloseResult.PayloadPath -and (Test-Path -LiteralPath $WriterCloseResult.PayloadPath -PathType Leaf)) {
                $actualRowCount = Get-CompressedPayloadVulnCount -Path $WriterCloseResult.PayloadPath
                if ($actualRowCount -ne $ExpectedRowCount) {
                    throw ("Normalized payload row count mismatch after direct payload streaming. Expected {0}, found {1} in '{2}'." -f $ExpectedRowCount, $actualRowCount, $WriterCloseResult.PayloadPath)
                }
            }
        }
    }
}

function New-NoOnboardedVulnerabilityMessage {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DataPath,

        [Parameter(Mandatory = $true)]
        [string]$SourceKind,

        [Parameter(Mandatory = $false)]
        [Nullable[int]]$DeviceProfileCount = $null,

        [Parameter(Mandatory = $false)]
        [Nullable[int]]$OnboardedDeviceProfileCount = $null,

        [Parameter(Mandatory = $false)]
        [Nullable[int]]$ContentTemplateCount = $null,

        [Parameter(Mandatory = $false)]
        [string[]]$InputLabels = @()
    )

    $messageParts = [System.Collections.Generic.List[string]]::new()
    $messageParts.Add(("No onboarded vulnerabilities were produced while normalizing {0} from '{1}'." -f $SourceKind, $DataPath)) | Out-Null

    $diagnosticParts = [System.Collections.Generic.List[string]]::new()
    if ($null -ne $DeviceProfileCount) {
        if ($null -ne $OnboardedDeviceProfileCount) {
            $diagnosticParts.Add(("device profiles {0} total/{1} onboarded" -f ([int]$DeviceProfileCount), ([int]$OnboardedDeviceProfileCount))) | Out-Null
        }
        else {
            $diagnosticParts.Add(("device profiles {0} total" -f ([int]$DeviceProfileCount))) | Out-Null
        }
    }

    if ($null -ne $ContentTemplateCount) {
        $diagnosticParts.Add(("content templates {0}" -f ([int]$ContentTemplateCount))) | Out-Null
    }

    $effectiveInputLabels = @($InputLabels | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($effectiveInputLabels.Count -gt 0) {
        $labelPreview = @($effectiveInputLabels | Select-Object -First 3)
        $labelSummary = if ($effectiveInputLabels.Count -gt $labelPreview.Count) {
            ("{0} (+{1} more)" -f ($labelPreview -join ', '), ($effectiveInputLabels.Count - $labelPreview.Count))
        }
        else {
            ($labelPreview -join ', ')
        }
        $diagnosticParts.Add(("streamed inputs {0} [{1}]" -f $effectiveInputLabels.Count, $labelSummary)) | Out-Null
    }

    if ($diagnosticParts.Count -gt 0) {
        $messageParts.Add(("Diagnostics: {0}." -f ($diagnosticParts -join '; '))) | Out-Null
    }

    if ($SourceKind -eq 'content-store refs') {
        $messageParts.Add('This usually means the export set is empty, every device profile has ob missing or false, or the content dictionary and ref sidecars are out of sync.') | Out-Null
    }
    else {
        $messageParts.Add('This usually means the export set is empty or every streamed row has IsOnboarded missing or false.') | Out-Null
    }

    return ($messageParts -join ' ')
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
        [hashtable]$AdvancedHuntingData = @{},

        [Parameter(Mandatory = $false)]
        [hashtable]$AdvancedHuntingDeviceUsers = @{},

        [Parameter(Mandatory = $false)]
        [hashtable]$AdvancedHuntingInventoryData = @{},

        [Parameter(Mandatory = $false)]
        [hashtable]$NvdCveData = @{},

        [Parameter(Mandatory = $false)]
        [string[]]$MergedRefPaths,

        [Parameter(Mandatory = $false)]
        [string]$PayloadOutputPath,

        [Parameter(Mandatory = $false)]
        [switch]$ConsumeLookupsOnPayloadClose
    )

    $lookups = $Context.Lookups
    $dateIndex = $Context.Indexes.dates
    $dateValueCache = $Context.DateValueCache

    $Context.Machines = $Machines
    $Context.AdvancedHuntingData = $AdvancedHuntingData
    $Context.AdvancedHuntingDeviceUsers = $AdvancedHuntingDeviceUsers
    $Context.AdvancedHuntingInventoryData = $AdvancedHuntingInventoryData
    $Context.NvdCveData = $NvdCveData
    $Context.HasNoTags = $false

    $dictionaryPath = Get-VulnContentDictionaryPath -BasePath $DataPath
    if (-not (Test-Path -LiteralPath $dictionaryPath -PathType Leaf)) {
        throw "Content dictionary '$dictionaryPath' was not found."
    }

    $deviceProfileIds = [System.Collections.Generic.List[string]]::new()
    $contentInventoryKeys = [System.Collections.Generic.List[object]]::new()
    $deviceLookupIndices = [System.Collections.Generic.List[int]]::new()
    $deviceOnboardedFlags = [System.Collections.Generic.List[bool]]::new()
    $contentLookupCache = [System.Collections.Generic.List[object]]::new()
    $processedCountRef = [ref]0
    $firstLastSwappedCountRef = [ref]0
    $writerState = $null
    $writerCloseResult = $null
    $lookupCountSummary = $null
    $consumeLookups = ($ConsumeLookupsOnPayloadClose -and -not [string]::IsNullOrWhiteSpace($PayloadOutputPath))

    foreach ($deviceProfile in @(Read-VulnContentDictionaryArrayEntries -Path $dictionaryPath -PropertyName 'deviceProfiles')) {
        $deviceId = [string](Get-VulnPropertyValue -InputObject $deviceProfile -Name 'id')
        $deviceProfileIds.Add($deviceId) | Out-Null
        $deviceLookupIndices.Add((Add-NormalizedDevice `
                -DeviceId $deviceId `
                -DeviceName ([string](Get-VulnPropertyValue -InputObject $deviceProfile -Name 'n')) `
                -GroupName ([string](Get-VulnPropertyValue -InputObject $deviceProfile -Name 'g')) `
                -OsPlatform ([string](Get-VulnPropertyValue -InputObject $deviceProfile -Name 'o')) `
                -OsVersion ([string](Get-VulnPropertyValue -InputObject $deviceProfile -Name 'ov')) `
                -MachineTags @(Get-StringArray -Value (Get-VulnPropertyValue -InputObject $deviceProfile -Name 't')) `
                -Context $Context)) | Out-Null
        $deviceOnboardedFlags.Add(((Get-VulnPropertyValue -InputObject $deviceProfile -Name 'ob') -eq $true)) | Out-Null
    }

    $deviceProfiles = $deviceProfileIds.ToArray()
    $deviceLookupIndices = $deviceLookupIndices.ToArray()
    $deviceOnboardedFlags = $deviceOnboardedFlags.ToArray()
    $deviceProfileCount = $deviceProfiles.Length
    $onboardedDeviceProfileCount = @($deviceOnboardedFlags | Where-Object { $_ }).Count
    $deviceProfileIds = $null

    foreach ($contentTemplate in @(Read-VulnContentDictionaryArrayEntries -Path $dictionaryPath -PropertyName 'contentTemplates')) {
        $softwareVendor = [string](Get-VulnPropertyValue -InputObject $contentTemplate -Name 'sv')
        $softwareName = [string](Get-VulnPropertyValue -InputObject $contentTemplate -Name 'sn')
        $softwareVersion = [string](Get-VulnPropertyValue -InputObject $contentTemplate -Name 'ver')

        $contentInventoryKeys.Add([object[]]@(
                $softwareVendor,
                $softwareName,
                $softwareVersion
            )) | Out-Null

        $contentLookupCache.Add((Resolve-NormalizedContentLookup `
                -SoftwareVendor $softwareVendor `
                -SoftwareName $softwareName `
                -RecommendationReference ([string](Get-VulnPropertyValue -InputObject $contentTemplate -Name 'rr')) `
                -CveId ([string](Get-VulnPropertyValue -InputObject $contentTemplate -Name 'c')) `
                -CvssScore (Get-VulnPropertyValue -InputObject $contentTemplate -Name 'sc') `
                -SeverityLevel ([string](Get-VulnPropertyValue -InputObject $contentTemplate -Name 'sev')) `
                -ExploitabilityLevel ([string](Get-VulnPropertyValue -InputObject $contentTemplate -Name 'ex')) `
                -CveUrl ([string](Get-VulnPropertyValue -InputObject $contentTemplate -Name 'bu')) `
                -CveBatchTitle ([string](Get-VulnPropertyValue -InputObject $contentTemplate -Name 'bt')) `
                -RecommendedSecurityUpdate ([string](Get-VulnPropertyValue -InputObject $contentTemplate -Name 'ru')) `
                -RecommendedSecurityUpdateId ([string](Get-VulnPropertyValue -InputObject $contentTemplate -Name 'rid')) `
                -RecommendedSecurityUpdateUrl ([string](Get-VulnPropertyValue -InputObject $contentTemplate -Name 'url')) `
                -SoftwareVersion $softwareVersion `
                -DiskPaths @(Get-StringArray -Value (Get-VulnPropertyValue -InputObject $contentTemplate -Name 'dp')) `
                -RegistryPaths @(Get-StringArray -Value (Get-VulnPropertyValue -InputObject $contentTemplate -Name 'rp')) `
                -SecurityUpdateAvailable ((Get-VulnPropertyValue -InputObject $contentTemplate -Name 'ua') -eq $true) `
                -Context $Context)) | Out-Null
    }

    $contentTemplates = $contentInventoryKeys.ToArray()
    $contentLookupCache = $contentLookupCache.ToArray()
    $contentTemplateCount = $contentTemplates.Length
    $contentInventoryKeys = $null

    try {
        $writerState = Open-NormalizedVulnWriter -VulnOutputPath $VulnOutputPath -VulnColumnDirectoryPath $VulnColumnDirectoryPath -PayloadOutputPath $PayloadOutputPath
        $compactRecord = [object[]]::new(11)
        $columnStates = if ($writerState.Mode -eq 'column') { $writerState.ColumnWriterSet.ColumnStates } else { $null }
        $jsonWriter = if ($writerState.Mode -eq 'column') { $null } else { $writerState.JsonWriter }

        $refPaths = [System.Collections.Generic.List[pscustomobject]]::new()
        if ($MergedRefPaths -and $MergedRefPaths.Count -gt 0) {
            # Use pre-merged ref paths (from observed-window cache or merge output)
            foreach ($mergedPath in $MergedRefPaths) {
                $refPaths.Add([PSCustomObject]@{
                    Path = $mergedPath
                    Label = (Split-Path -Leaf $mergedPath)
                })
            }
        }
        else {
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
        }

        foreach ($refPath in $refPaths) {
            # Inline streaming — eliminates 1.5M scriptblock invocations from
            # Invoke-VulnNdjsonLineAction. Uses direct .NET GZip + buffer scan.
            $refFileStream = [System.IO.File]::OpenRead([string]$refPath.Path)
            $refContentStream = if (([string]$refPath.Path).EndsWith('.gz', [System.StringComparison]::OrdinalIgnoreCase)) {
                [System.IO.Compression.GZipStream]::new($refFileStream, [System.IO.Compression.CompressionMode]::Decompress)
            } else { $refFileStream }
            $refBuffer = [byte[]]::new(65536)
            $refCarryStream = [System.IO.MemoryStream]::new()
            try {
                while (($refBytesRead = $refContentStream.Read($refBuffer, 0, $refBuffer.Length)) -gt 0) {
                    $segmentStart = 0
                    for ($byteIndex = 0; $byteIndex -lt $refBytesRead; $byteIndex++) {
                        if ($refBuffer[$byteIndex] -ne 0x0A) { continue }

                        $segmentLength = $byteIndex - $segmentStart
                        if ($segmentLength -gt 0 -and $refBuffer[$byteIndex - 1] -eq 0x0D) { $segmentLength-- }

                        $jsonLine = $null
                        if ($refCarryStream.Length -gt 0) {
                            if ($segmentLength -gt 0) { $refCarryStream.Write($refBuffer, $segmentStart, $segmentLength) }
                            if ($refCarryStream.Length -gt 0) { $jsonLine = [System.Text.Encoding]::UTF8.GetString($refCarryStream.ToArray()) }
                            $refCarryStream.SetLength(0)
                        }
                        elseif ($segmentLength -gt 0) {
                            $jsonLine = [System.Text.Encoding]::UTF8.GetString($refBuffer, $segmentStart, $segmentLength)
                        }
                        $segmentStart = $byteIndex + 1

                        if ([string]::IsNullOrWhiteSpace($jsonLine)) { continue }

                        # --- Inline ref processing (was the scriptblock body) ---
                        $document = [System.Text.Json.JsonDocument]::Parse($jsonLine)
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

                            if (($deviceProfileIndexValue -lt 0) -or ($deviceProfileIndexValue -ge $deviceProfileCount)) { continue }
                            if (($contentTemplateIndexValue -lt 0) -or ($contentTemplateIndexValue -ge $contentTemplateCount)) { continue }
                            if (-not $deviceOnboardedFlags[$deviceProfileIndexValue]) { continue }

                            $processedCountRef.Value++

                            $firstSeen = $null
                            $lastSeen = $null
                            if ($null -ne $firstSeenValue) {
                                $firstSeenText = [string]$firstSeenValue
                                if ($dateValueCache.ContainsKey($firstSeenText)) {
                                    $firstSeen = $dateValueCache[$firstSeenText]
                                }
                                else {
                                    $firstSeen = if ($firstSeenText.Length -ge 10 -and $firstSeenText[4] -eq '-' -and $firstSeenText[7] -eq '-') { $firstSeenText.Substring(0, 10) } else { Convert-ToYmdDate -DateValue $firstSeenText }
                                    $dateValueCache[$firstSeenText] = $firstSeen
                                }
                            }

                            if ($null -ne $lastSeenValue) {
                                $lastSeenText = [string]$lastSeenValue
                                if ($dateValueCache.ContainsKey($lastSeenText)) {
                                    $lastSeen = $dateValueCache[$lastSeenText]
                                }
                                else {
                                    $lastSeen = if ($lastSeenText.Length -ge 10 -and $lastSeenText[4] -eq '-' -and $lastSeenText[7] -eq '-') { $lastSeenText.Substring(0, 10) } else { Convert-ToYmdDate -DateValue $lastSeenText }
                                    $dateValueCache[$lastSeenText] = $lastSeen
                                }
                            }

                            if ($firstSeen -and $lastSeen -and [datetime]$firstSeen -gt [datetime]$lastSeen) {
                                $swappedSeenValue = $firstSeen
                                $firstSeen = $lastSeen
                                $lastSeen = $swappedSeenValue
                                $firstLastSwappedCountRef.Value++
                            }

                            if (-not $firstSeen) { $firstSeen = '' }
                            if (-not $lastSeen) { $lastSeen = '' }

                            $contentLookup = $contentLookupCache[$contentTemplateIndexValue]
                            $contentTemplate = $contentTemplates[$contentTemplateIndexValue]
                            $deviceProfileId = $deviceProfiles[$deviceProfileIndexValue]
                            $compactRecord[0] = $deviceLookupIndices[$deviceProfileIndexValue]
                            $compactRecord[1] = $contentLookup.cve
                            $compactRecord[2] = $contentLookup.sw
                            $compactRecord[3] = $contentLookup.ver
                            $compactRecord[4] = Get-OrCreateIndex -value $firstSeen -list $lookups.dates -indexMap $dateIndex
                            $compactRecord[5] = Get-OrCreateIndex -value $lastSeen -list $lookups.dates -indexMap $dateIndex
                            $compactRecord[6] = $contentLookup.ua
                            $compactRecord[7] = $contentLookup.upd
                            $compactRecord[8] = $contentLookup.dp
                            $compactRecord[9] = $contentLookup.rp
                            $compactRecord[10] = Resolve-NormalizedInventoryLookup `
                                -DeviceId ([string]$deviceProfileId) `
                                -SoftwareVendor ([string]$contentTemplate[0]) `
                                -SoftwareName ([string]$contentTemplate[1]) `
                                -SoftwareVersion ([string]$contentTemplate[2]) `
                                -Context $Context

                            if ($columnStates) {
                                for ($columnIndex = 0; $columnIndex -lt 11; $columnIndex++) {
                                    $columnState = $columnStates[$columnIndex]
                                    $columnValue = $compactRecord[$columnIndex]
                                    $buffer = $columnState.Buffer

                                    if ($columnState.HasValue) {
                                        [void]$buffer.Append(',')
                                    }
                                    else {
                                        $columnState.HasValue = $true
                                    }

                                    if ($null -eq $columnValue) {
                                        [void]$buffer.Append('null')
                                    }
                                    elseif ($columnValue -is [System.Collections.IEnumerable] -and $columnValue -isnot [string]) {
                                        [void]$buffer.Append('[')
                                        $isFirstColumnValue = $true
                                        foreach ($nestedValue in $columnValue) {
                                            if ($isFirstColumnValue) {
                                                $isFirstColumnValue = $false
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
                                        [void]$buffer.Append([string]$columnValue)
                                    }

                                    if ($buffer.Length -ge 131072) {
                                        $columnState.StreamWriter.Write($buffer.ToString())
                                        [void]$buffer.Clear()
                                    }
                                }
                            }
                            else {
                                Write-CompactVulnRecordJson -Writer $jsonWriter -Record $compactRecord
                            }

                            if (($processedCountRef.Value % 50000) -eq 0) {
                                Write-Information ("  Processed {0} onboarded vulnerability record(s)..." -f $processedCountRef.Value) -InformationAction Continue
                            }

                            if (($processedCountRef.Value % 100000) -eq 0) {
                                Sync-NormalizedVulnWriter -WriterState $writerState
                                Invoke-FullGarbageCollection
                            }
                        }
                        finally {
                            $document.Dispose()
                        }
                    }

                    $remainingLength = $refBytesRead - $segmentStart
                    if ($remainingLength -gt 0) { $refCarryStream.Write($refBuffer, $segmentStart, $remainingLength) }
                }

                # Process final carry bytes
                if ($refCarryStream.Length -gt 0) {
                    $lineBytes = $refCarryStream.ToArray()
                    $lineLength = $lineBytes.Length
                    if ($lineLength -gt 0 -and $lineBytes[$lineLength - 1] -eq 0x0D) { $lineLength-- }
                    if ($lineLength -gt 0) {
                        $jsonLine = [System.Text.Encoding]::UTF8.GetString($lineBytes, 0, $lineLength)
                        if (-not [string]::IsNullOrWhiteSpace($jsonLine)) {
                            $document = [System.Text.Json.JsonDocument]::Parse($jsonLine)
                            try {
                                $root = $document.RootElement
                                $elements = $root.EnumerateArray()
                                [void]$elements.MoveNext()
                                [void]$elements.MoveNext()
                                $dpv = $elements.Current.GetInt32()
                                [void]$elements.MoveNext()
                                $ctv = $elements.Current.GetInt32()
                                if (($dpv -ge 0) -and ($dpv -lt $deviceProfileCount) -and ($ctv -ge 0) -and ($ctv -lt $contentTemplateCount) -and $deviceOnboardedFlags[$dpv]) {
                                    [void]$elements.MoveNext()
                                    $fv = if ($elements.Current.ValueKind -eq [System.Text.Json.JsonValueKind]::Null) { $null } else { $elements.Current.GetString() }
                                    [void]$elements.MoveNext()
                                    $lv = if ($elements.Current.ValueKind -eq [System.Text.Json.JsonValueKind]::Null) { $null } else { $elements.Current.GetString() }
                                    $processedCountRef.Value++

                                    $firstSeen = $null
                                    $lastSeen = $null
                                    if ($null -ne $fv) {
                                        $firstSeenText = [string]$fv
                                        if ($dateValueCache.ContainsKey($firstSeenText)) {
                                            $firstSeen = $dateValueCache[$firstSeenText]
                                        }
                                        else {
                                            $firstSeen = if ($firstSeenText.Length -ge 10 -and $firstSeenText[4] -eq '-' -and $firstSeenText[7] -eq '-') { $firstSeenText.Substring(0, 10) } else { Convert-ToYmdDate -DateValue $firstSeenText }
                                            $dateValueCache[$firstSeenText] = $firstSeen
                                        }
                                    }

                                    if ($null -ne $lv) {
                                        $lastSeenText = [string]$lv
                                        if ($dateValueCache.ContainsKey($lastSeenText)) {
                                            $lastSeen = $dateValueCache[$lastSeenText]
                                        }
                                        else {
                                            $lastSeen = if ($lastSeenText.Length -ge 10 -and $lastSeenText[4] -eq '-' -and $lastSeenText[7] -eq '-') { $lastSeenText.Substring(0, 10) } else { Convert-ToYmdDate -DateValue $lastSeenText }
                                            $dateValueCache[$lastSeenText] = $lastSeen
                                        }
                                    }

                                    if ($firstSeen -and $lastSeen -and [datetime]$firstSeen -gt [datetime]$lastSeen) {
                                        $swappedSeenValue = $firstSeen
                                        $firstSeen = $lastSeen
                                        $lastSeen = $swappedSeenValue
                                        $firstLastSwappedCountRef.Value++
                                    }

                                    if (-not $firstSeen) { $firstSeen = '' }
                                    if (-not $lastSeen) { $lastSeen = '' }

                                    $contentLookup = $contentLookupCache[$ctv]
                                    $contentTemplate = $contentTemplates[$ctv]
                                    $deviceProfileId = $deviceProfiles[$dpv]
                                    $compactRecord[0] = $deviceLookupIndices[$dpv]
                                    $compactRecord[1] = $contentLookup.cve
                                    $compactRecord[2] = $contentLookup.sw
                                    $compactRecord[3] = $contentLookup.ver
                                    $compactRecord[4] = Get-OrCreateIndex -value $firstSeen -list $lookups.dates -indexMap $dateIndex
                                    $compactRecord[5] = Get-OrCreateIndex -value $lastSeen -list $lookups.dates -indexMap $dateIndex
                                    $compactRecord[6] = $contentLookup.ua
                                    $compactRecord[7] = $contentLookup.upd
                                    $compactRecord[8] = $contentLookup.dp
                                    $compactRecord[9] = $contentLookup.rp
                                    $compactRecord[10] = Resolve-NormalizedInventoryLookup `
                                        -DeviceId ([string]$deviceProfileId) `
                                        -SoftwareVendor ([string]$contentTemplate[0]) `
                                        -SoftwareName ([string]$contentTemplate[1]) `
                                        -SoftwareVersion ([string]$contentTemplate[2]) `
                                        -Context $Context

                                    if ($columnStates) {
                                        for ($columnIndex = 0; $columnIndex -lt 11; $columnIndex++) {
                                            $columnState = $columnStates[$columnIndex]
                                            $columnValue = $compactRecord[$columnIndex]
                                            $buffer = $columnState.Buffer

                                            if ($columnState.HasValue) {
                                                [void]$buffer.Append(',')
                                            }
                                            else {
                                                $columnState.HasValue = $true
                                            }

                                            if ($null -eq $columnValue) {
                                                [void]$buffer.Append('null')
                                            }
                                            elseif ($columnValue -is [System.Collections.IEnumerable] -and $columnValue -isnot [string]) {
                                                [void]$buffer.Append('[')
                                                $isFirstColumnValue = $true
                                                foreach ($nestedValue in $columnValue) {
                                                    if ($isFirstColumnValue) {
                                                        $isFirstColumnValue = $false
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
                                                [void]$buffer.Append([string]$columnValue)
                                            }

                                            if ($buffer.Length -ge 131072) {
                                                $columnState.StreamWriter.Write($buffer.ToString())
                                                [void]$buffer.Clear()
                                            }
                                        }
                                    }
                                    else {
                                        Write-CompactVulnRecordJson -Writer $jsonWriter -Record $compactRecord
                                    }

                                    if (($processedCountRef.Value % 50000) -eq 0) {
                                        Write-Information ("  Processed {0} onboarded vulnerability record(s)..." -f $processedCountRef.Value) -InformationAction Continue
                                    }

                                    if (($processedCountRef.Value % 100000) -eq 0) {
                                        Sync-NormalizedVulnWriter -WriterState $writerState
                                        Invoke-FullGarbageCollection
                                    }
                                }
                            }
                            finally { $document.Dispose() }
                        }
                    }
                }
            }
            finally {
                $refCarryStream.Dispose()
                if ($refContentStream -ne $refFileStream) { $refContentStream.Dispose() }
                $refFileStream.Dispose()
            }
        }

        Sync-NormalizedVulnWriter -WriterState $writerState

        # Payload finalization only needs the compact lookup collections. Release
        # the much larger content-store scaffolding first so hosted Automation
        # does not carry that transient state into lookup serialization.
        foreach ($transientArray in @($deviceProfiles, $contentTemplates, $deviceLookupIndices, $deviceOnboardedFlags, $contentLookupCache)) {
            if ($null -ne $transientArray) {
                [System.Array]::Clear($transientArray, 0, $transientArray.Length)
            }
        }

        if ($null -ne $refPaths) {
            $refPaths.Clear()
        }

        $Context.Machines = @{}
        $Context.AdvancedHuntingData = @{}
        $Context.AdvancedHuntingDeviceUsers = @{}
        $Context.AdvancedHuntingInventoryData = @{}
        $Context.NvdCveData = @{}

        $dateValueCacheProperty = $Context.PSObject.Properties['DateValueCache']
        if ($null -ne $dateValueCacheProperty -and $null -ne $dateValueCacheProperty.Value) {
            $dateValueCacheProperty.Value.Clear()
        }

        $deviceProfiles = $null
        $contentTemplates = $null
        $deviceLookupIndices = $null
        $deviceOnboardedFlags = $null
        $contentLookupCache = $null
        $refPaths = $null

        if (-not [string]::IsNullOrWhiteSpace($PayloadOutputPath)) {
            if ($consumeLookups) {
                $lookupCountSummary = Get-NormalizedLookupCountSummary -Lookups $Context.Lookups
            }
            Invoke-FullGarbageCollection
            if (Get-Command -Name Write-MemoryUsage -ErrorAction SilentlyContinue) {
                $null = Write-MemoryUsage -Label 'Pre-PayloadClose'
            }
        }
    }
    finally {
        if ($writerState) {
            $writerCloseResult = Close-NormalizedVulnWriter -WriterState $writerState -Lookups $Context.Lookups -ConsumeLookups:$consumeLookups
        }
    }

    Test-NormalizedWriterRowCount -WriterCloseResult $writerCloseResult -ExpectedRowCount $processedCountRef.Value

    if ($processedCountRef.Value -eq 0) {
        $refLabels = New-Object 'System.Collections.Generic.List[string]'
        foreach ($refPath in $refPaths) {
            $refLabels.Add([string]$refPath.Label) | Out-Null
        }

        throw (New-NoOnboardedVulnerabilityMessage `
                -DataPath $DataPath `
                -SourceKind 'content-store refs' `
                -DeviceProfileCount $deviceProfileCount `
                -OnboardedDeviceProfileCount $onboardedDeviceProfileCount `
                -ContentTemplateCount $contentTemplateCount `
                -InputLabels $refLabels.ToArray())
    }

    if ($null -eq $lookupCountSummary) {
        $lookupCountSummary = Get-NormalizedLookupCountSummary -Lookups $Context.Lookups
    }

    return [PSCustomObject]@{
        ProcessedCount = $processedCountRef.Value
        FirstLastSwappedCount = $firstLastSwappedCountRef.Value
        HasNoTags = ($Context.HasNoTags -eq $true)
        VulnsPath = $writerCloseResult.VulnsPath
        VulnColumnPaths = $writerCloseResult.VulnColumnPaths
        PayloadPath = $writerCloseResult.PayloadPath
        DeviceCount = [int]$lookupCountSummary.DeviceCount
        CveCount = [int]$lookupCountSummary.CveCount
        SoftwareCount = [int]$lookupCountSummary.SoftwareCount
        VendorCount = [int]$lookupCountSummary.VendorCount
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
        [hashtable]$AdvancedHuntingData = @{},

        [Parameter(Mandatory = $false)]
        [hashtable]$AdvancedHuntingDeviceUsers = @{},

        [Parameter(Mandatory = $false)]
        [hashtable]$AdvancedHuntingInventoryData = @{},

        [Parameter(Mandatory = $false)]
        [hashtable]$NvdCveData = @{},

        [Parameter(Mandatory = $false)]
        [string]$PayloadOutputPath,

        [Parameter(Mandatory = $false)]
        [switch]$ConsumeLookupsOnPayloadClose
    )

    $Context.Machines = $Machines
    $Context.AdvancedHuntingData = $AdvancedHuntingData
    $Context.AdvancedHuntingDeviceUsers = $AdvancedHuntingDeviceUsers
    $Context.AdvancedHuntingInventoryData = $AdvancedHuntingInventoryData
    $Context.NvdCveData = $NvdCveData
    $Context.HasNoTags = $false

    $processedCountRef = [ref]0
    $firstLastSwappedCountRef = [ref]0
    $writerState = $null
    $writerCloseResult = $null
    $compactRecord = [object[]]@(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1)
    $lookupCountSummary = $null
    $consumeLookups = ($ConsumeLookupsOnPayloadClose -and -not [string]::IsNullOrWhiteSpace($PayloadOutputPath))

    try {
        $writerState = Open-NormalizedVulnWriter -VulnOutputPath $VulnOutputPath -VulnColumnDirectoryPath $VulnColumnDirectoryPath -PayloadOutputPath $PayloadOutputPath

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

                        $isOnboarded = $false
                        $deviceId = ''
                        $deviceName = ''
                        $groupName = ''
                        $osPlatform = ''
                        $osVersion = ''
                        $machineTags = @()
                        $softwareVendor = ''
                        $softwareName = ''
                        $recommendationReference = ''
                        $cveId = $null
                        $cvssScore = $null
                        $severityLevel = $null
                        $exploitabilityLevel = $null
                        $cveBatchUrl = $null
                        $cveBatchTitle = $null
                        $recUpdate = $null
                        $recUpdateId = $null
                        $recUpdateUrl = $null
                        $seenFirstValue = $null
                        $seenLastValue = $null
                        $versionStr = $null
                        $rawDiskPaths = @()
                        $rawRegPaths = @()
                        $secUpdateAvail = $false

                        foreach ($jsonProperty in $root.EnumerateObject()) {
                            $propertyValue = $jsonProperty.Value
                            switch ($jsonProperty.Name) {
                                'IsOnboarded' {
                                    if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::True) {
                                        $isOnboarded = $true
                                    }
                                    elseif ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::False) {
                                        $isOnboarded = $false
                                    }
                                    elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                        $isOnboarded = ((Convert-JsonElementToScalarValue -Element $propertyValue) -eq $true)
                                    }
                                }
                                'DeviceId' {
                                    if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                        $deviceId = $propertyValue.GetString()
                                    }
                                    elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                        $deviceId = [string](Convert-JsonElementToScalarValue -Element $propertyValue)
                                    }
                                }
                                'DeviceName' {
                                    if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                        $deviceName = $propertyValue.GetString()
                                    }
                                    elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                        $deviceName = [string](Convert-JsonElementToScalarValue -Element $propertyValue)
                                    }
                                }
                                'RbacGroupName' {
                                    if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                        $groupName = $propertyValue.GetString()
                                    }
                                    elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                        $groupName = [string](Convert-JsonElementToScalarValue -Element $propertyValue)
                                    }
                                }
                                'OSPlatform' {
                                    if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                        $osPlatform = $propertyValue.GetString()
                                    }
                                    elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                        $osPlatform = [string](Convert-JsonElementToScalarValue -Element $propertyValue)
                                    }
                                }
                                'OSVersion' {
                                    if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                        $osVersion = $propertyValue.GetString()
                                    }
                                    elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                        $osVersion = [string](Convert-JsonElementToScalarValue -Element $propertyValue)
                                    }
                                }
                                'MachineTags' {
                                    if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::Array) {
                                        $tagValues = [System.Collections.Generic.List[string]]::new()
                                        foreach ($tagValueElement in $propertyValue.EnumerateArray()) {
                                            $tagValue = if ($tagValueElement.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                                $tagValueElement.GetString()
                                            }
                                            else {
                                                Convert-JsonElementToScalarValue -Element $tagValueElement
                                            }
                                            if ($null -ne $tagValue -and -not [string]::IsNullOrWhiteSpace([string]$tagValue)) {
                                                [void]$tagValues.Add([string]$tagValue)
                                            }
                                        }
                                        $machineTags = [string[]]$tagValues.ToArray()
                                    }
                                }
                                'SoftwareVendor' {
                                    if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                        $softwareVendor = $propertyValue.GetString()
                                    }
                                    elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                        $softwareVendor = [string](Convert-JsonElementToScalarValue -Element $propertyValue)
                                    }
                                }
                                'SoftwareName' {
                                    if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                        $softwareName = $propertyValue.GetString()
                                    }
                                    elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                        $softwareName = [string](Convert-JsonElementToScalarValue -Element $propertyValue)
                                    }
                                }
                                'RecommendationReference' {
                                    if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                        $recommendationReference = $propertyValue.GetString()
                                    }
                                    elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                        $recommendationReference = [string](Convert-JsonElementToScalarValue -Element $propertyValue)
                                    }
                                }
                                'CveId' {
                                    if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                        $cveId = $propertyValue.GetString()
                                    }
                                    elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                        $cveId = Convert-JsonElementToScalarValue -Element $propertyValue
                                    }
                                }
                                'CvssScore' {
                                    if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                        $cvssScore = $propertyValue.GetString()
                                    }
                                    elseif ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::Number) {
                                        $cvssInt64 = 0L
                                        if ($propertyValue.TryGetInt64([ref]$cvssInt64)) {
                                            $cvssScore = $cvssInt64
                                        }
                                        else {
                                            $cvssDouble = 0.0
                                            if ($propertyValue.TryGetDouble([ref]$cvssDouble)) {
                                                $cvssScore = $cvssDouble
                                            }
                                            else {
                                                $cvssScore = $propertyValue.GetRawText()
                                            }
                                        }
                                    }
                                    elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                        $cvssScore = Convert-JsonElementToScalarValue -Element $propertyValue
                                    }
                                }
                                'VulnerabilitySeverityLevel' {
                                    if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                        $severityLevel = $propertyValue.GetString()
                                    }
                                    elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                        $severityLevel = Convert-JsonElementToScalarValue -Element $propertyValue
                                    }
                                }
                                'ExploitabilityLevel' {
                                    if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                        $exploitabilityLevel = $propertyValue.GetString()
                                    }
                                    elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                        $exploitabilityLevel = Convert-JsonElementToScalarValue -Element $propertyValue
                                    }
                                }
                                'CveBatchUrl' {
                                    if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                        $cveBatchUrl = $propertyValue.GetString()
                                    }
                                    elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                        $cveBatchUrl = Convert-JsonElementToScalarValue -Element $propertyValue
                                    }
                                }
                                'CveBatchTitle' {
                                    if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                        $cveBatchTitle = $propertyValue.GetString()
                                    }
                                    elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                        $cveBatchTitle = Convert-JsonElementToScalarValue -Element $propertyValue
                                    }
                                }
                                'RecommendedSecurityUpdate' {
                                    if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                        $recUpdate = $propertyValue.GetString()
                                    }
                                    elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                        $recUpdate = Convert-JsonElementToScalarValue -Element $propertyValue
                                    }
                                }
                                'RecommendedSecurityUpdateId' {
                                    if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                        $recUpdateId = $propertyValue.GetString()
                                    }
                                    elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                        $recUpdateId = Convert-JsonElementToScalarValue -Element $propertyValue
                                    }
                                }
                                'RecommendedSecurityUpdateUrl' {
                                    if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                        $recUpdateUrl = $propertyValue.GetString()
                                    }
                                    elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                        $recUpdateUrl = Convert-JsonElementToScalarValue -Element $propertyValue
                                    }
                                }
                                'FirstSeenTimestamp' {
                                    if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                        $seenFirstValue = $propertyValue.GetString()
                                    }
                                    elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                        $seenFirstValue = Convert-JsonElementToScalarValue -Element $propertyValue
                                    }
                                }
                                'LastSeenTimestamp' {
                                    if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                        $seenLastValue = $propertyValue.GetString()
                                    }
                                    elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                        $seenLastValue = Convert-JsonElementToScalarValue -Element $propertyValue
                                    }
                                }
                                'SoftwareVersion' {
                                    if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                        $versionStr = $propertyValue.GetString()
                                    }
                                    elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                        $versionStr = Convert-JsonElementToScalarValue -Element $propertyValue
                                    }
                                }
                                'DiskPaths' {
                                    if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::Array) {
                                        $diskPathValues = [System.Collections.Generic.List[string]]::new()
                                        foreach ($diskPathElement in $propertyValue.EnumerateArray()) {
                                            $diskPathValue = if ($diskPathElement.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                                $diskPathElement.GetString()
                                            }
                                            else {
                                                Convert-JsonElementToScalarValue -Element $diskPathElement
                                            }
                                            if ($null -ne $diskPathValue -and -not [string]::IsNullOrWhiteSpace([string]$diskPathValue)) {
                                                [void]$diskPathValues.Add([string]$diskPathValue)
                                            }
                                        }
                                        $rawDiskPaths = [string[]]$diskPathValues.ToArray()
                                    }
                                }
                                'RegistryPaths' {
                                    if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::Array) {
                                        $regPathValues = [System.Collections.Generic.List[string]]::new()
                                        foreach ($regPathElement in $propertyValue.EnumerateArray()) {
                                            $regPathValue = if ($regPathElement.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                                $regPathElement.GetString()
                                            }
                                            else {
                                                Convert-JsonElementToScalarValue -Element $regPathElement
                                            }
                                            if ($null -ne $regPathValue -and -not [string]::IsNullOrWhiteSpace([string]$regPathValue)) {
                                                [void]$regPathValues.Add([string]$regPathValue)
                                            }
                                        }
                                        $rawRegPaths = [string[]]$regPathValues.ToArray()
                                    }
                                }
                                'SecurityUpdateAvailable' {
                                    if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::True) {
                                        $secUpdateAvail = $true
                                    }
                                    elseif ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::False) {
                                        $secUpdateAvail = $false
                                    }
                                    elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                        $secUpdateAvail = ((Convert-JsonElementToScalarValue -Element $propertyValue) -eq $true)
                                    }
                                }
                            }
                        }

                        if ($isOnboarded -ne $true) { return }

                        Write-NormalizedSourceRow `
                            -WriterState $writerState `
                            -Record $compactRecord `
                            -ProcessedCount $processedCountRef `
                            -DeviceId $deviceId `
                            -DeviceName $deviceName `
                            -GroupName $groupName `
                            -OsPlatform $osPlatform `
                            -OsVersion $osVersion `
                            -MachineTags $machineTags `
                            -SoftwareVendor $softwareVendor `
                            -SoftwareName $softwareName `
                            -RecommendationReference $recommendationReference `
                            -CveId $cveId `
                            -CvssScore $cvssScore `
                            -SeverityLevel $severityLevel `
                            -ExploitabilityLevel $exploitabilityLevel `
                            -CveUrl $cveBatchUrl `
                            -CveBatchTitle $cveBatchTitle `
                            -RecommendedSecurityUpdate $recUpdate `
                            -RecommendedSecurityUpdateId $recUpdateId `
                            -RecommendedSecurityUpdateUrl $recUpdateUrl `
                            -SoftwareVersion $versionStr `
                            -DiskPaths @($rawDiskPaths) `
                            -RegistryPaths @($rawRegPaths) `
                            -SecurityUpdateAvailable $secUpdateAvail `
                            -Context $Context `
                            -FirstSeenValue $seenFirstValue `
                            -LastSeenValue $seenLastValue `
                            -FirstLastSwappedCount $firstLastSwappedCountRef
                }

                if (Get-Command -Name Write-MemoryUsage -ErrorAction SilentlyContinue) {
                    Write-MemoryUsage -Label ("VulnStore " + $storePath.Label + " End")
                }
            }
        } | Out-Null

        Sync-NormalizedVulnWriter -WriterState $writerState

        if ($consumeLookups) {
            $lookupCountSummary = Get-NormalizedLookupCountSummary -Lookups $Context.Lookups
        }
    }
    finally {
        if ($writerState) {
            $writerCloseResult = Close-NormalizedVulnWriter -WriterState $writerState -Lookups $Context.Lookups -ConsumeLookups:$consumeLookups
        }
    }

    Test-NormalizedWriterRowCount -WriterCloseResult $writerCloseResult -ExpectedRowCount $processedCountRef.Value

    if ($null -eq $lookupCountSummary) {
        $lookupCountSummary = Get-NormalizedLookupCountSummary -Lookups $Context.Lookups
    }

    return [PSCustomObject]@{
        ProcessedCount = $processedCountRef.Value
        FirstLastSwappedCount = $firstLastSwappedCountRef.Value
        HasNoTags = ($Context.HasNoTags -eq $true)
        VulnsPath = $writerCloseResult.VulnsPath
        VulnColumnPaths = $writerCloseResult.VulnColumnPaths
        PayloadPath = $writerCloseResult.PayloadPath
        DeviceCount = [int]$lookupCountSummary.DeviceCount
        CveCount = [int]$lookupCountSummary.CveCount
        SoftwareCount = [int]$lookupCountSummary.SoftwareCount
        VendorCount = [int]$lookupCountSummary.VendorCount
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

function Test-VulnObservedWindowMergeable {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        $CurrentWindow,

        [Parameter(Mandatory = $true)]
        $CandidateWindow,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 30)]
        [int]$AllowedGapDays = 1
    )

    if (
        [string]::IsNullOrWhiteSpace($CurrentWindow.FirstSeenTimestamp) -or
        [string]::IsNullOrWhiteSpace($CurrentWindow.LastSeenTimestamp) -or
        [string]::IsNullOrWhiteSpace($CandidateWindow.FirstSeenTimestamp) -or
        [string]::IsNullOrWhiteSpace($CandidateWindow.LastSeenTimestamp)
    ) {
        return $false
    }

    $mergeThreshold = ([datetime]$CurrentWindow.LastSeenTimestamp).AddDays($AllowedGapDays + 1).ToString('yyyy-MM-dd')
    return ([datetime]$CandidateWindow.FirstSeenTimestamp -le [datetime]$mergeThreshold)
}

function Merge-VulnObservedWindowSequence {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Items,

        [Parameter(Mandatory = $true)]
        [scriptblock]$GetWindow,

        [Parameter(Mandatory = $true)]
        [scriptblock]$CreateItem,

        [Parameter(Mandatory = $true)]
        [scriptblock]$CreateMergedItem,

        [Parameter(Mandatory = $true)]
        [scriptblock]$FinalizeItem,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 30)]
        [int]$AllowedGapDays = 1
    )

    $itemArray = @($Items)
    if ($itemArray.Count -eq 0) {
        return @()
    }

    if ($itemArray.Count -eq 1) {
        $singleItemList = [System.Collections.Generic.List[object]]::new()
        $singleItemList.Add((& $CreateItem $itemArray[0]))
        return @($singleItemList)
    }

    $mergedItems = [System.Collections.Generic.List[object]]::new()
    $current = & $CreateItem $itemArray[0]
    $currentWindow = & $GetWindow $current

    for ($index = 1; $index -lt $itemArray.Count; $index++) {
        $candidate = $itemArray[$index]
        $candidateWindow = & $GetWindow $candidate

        if (Test-VulnObservedWindowMergeable -CurrentWindow $currentWindow -CandidateWindow $candidateWindow -AllowedGapDays $AllowedGapDays) {
            $mergedFirstSeen = Get-MinVulnDate -Primary $currentWindow.FirstSeenTimestamp -Secondary $candidateWindow.FirstSeenTimestamp
            $mergedLastSeen = Get-MaxVulnDate -Primary $currentWindow.LastSeenTimestamp -Secondary $candidateWindow.LastSeenTimestamp
            $current = & $CreateMergedItem $candidate $mergedFirstSeen $mergedLastSeen
            $currentWindow = [PSCustomObject]@{
                FirstSeenTimestamp = $mergedFirstSeen
                LastSeenTimestamp = $mergedLastSeen
            }
            continue
        }

        $mergedItems.Add((& $FinalizeItem $current $currentWindow))
        $current = & $CreateItem $candidate
        $currentWindow = $candidateWindow
    }

    $mergedItems.Add((& $FinalizeItem $current $currentWindow))
    return @($mergedItems)
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

        foreach ($mergedRow in @(Merge-VulnObservedWindowSequence `
                -Items $items `
                -AllowedGapDays $AllowedGapDays `
                -GetWindow {
                    param($item)
                    Get-NormalizedVulnSeenWindow `
                        -FirstSeenValue (Get-VulnPropertyValue -InputObject $item -Name 'FirstSeenTimestamp') `
                        -LastSeenValue (Get-VulnPropertyValue -InputObject $item -Name 'LastSeenTimestamp')
                } `
                -CreateItem {
                    param($item)
                    Copy-VulnRecord -Record $item
                } `
                -CreateMergedItem {
                    param($candidate, $firstSeenTimestamp, $lastSeenTimestamp)
                    $merged = Copy-VulnRecord -Record $candidate
                    $merged.FirstSeenTimestamp = $firstSeenTimestamp
                    $merged.LastSeenTimestamp = $lastSeenTimestamp
                    $merged
                } `
                -FinalizeItem {
                    param($item)
                    $item
                })) {
            $mergedRows.Add($mergedRow)
        }
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
        [ref]$OutputRowCount = ([ref]0),

        [Parameter(Mandatory = $false)]
        [ValidateRange(4, 256)]
        [int]$PartitionCount = 128
    )

    # Disk-partitioned merge: scatter rows to temp partition files by identity
    # key hash, then process each partition independently. Peak memory is
    # ~(totalRows / PartitionCount) instead of totalRows.
    $partitionDir = Join-Path ([System.IO.Path]::GetTempPath()) ('owmerge-' + [System.Guid]::NewGuid().ToString('N'))
    [void](New-Item -ItemType Directory -Path $partitionDir -Force)

    $sourceRowCount = 0
    $mergedRowCount = 0
    $partitionWriters = [System.IO.StreamWriter[]]::new($PartitionCount)
    $scatterJsonOptions = [System.Text.Json.JsonSerializerOptions]::new()
    $scatterJsonOptions.WriteIndented = $false
    $scatterJsonOptions.MaxDepth = 20

    try {
        # Pass 1 — scatter: stream source rows to partition files by identity hash
        # IMPORTANT: Use pipeline (| ForEach-Object) not foreach() to avoid
        # collecting all source rows into memory at once.
        & $Source | ForEach-Object {
            $row = $_
            if ($null -eq $row) { return }
            $sourceRowCount++

            $identityKey = Get-VulnObservedWindowIdentityKey -Row $row
            $hash = [uint32]([int64]$identityKey.GetHashCode() -band 0xFFFFFFFFL)
            $bucket = [int]($hash % [uint32]$PartitionCount)

            if ($null -eq $partitionWriters[$bucket]) {
                $partPath = Join-Path $partitionDir "p$bucket.ndjson"
                $partitionWriters[$bucket] = [System.IO.StreamWriter]::new(
                    [System.IO.File]::Create($partPath),
                    [System.Text.UTF8Encoding]::new($false))
            }
            $dict = [System.Collections.Generic.Dictionary[string,object]]::new()
            foreach ($prop in $row.PSObject.Properties) { $dict[$prop.Name] = $prop.Value }
            $partitionWriters[$bucket].WriteLine([System.Text.Json.JsonSerializer]::Serialize($dict, $scatterJsonOptions))
        }

        # Flush and close all partition writers
        for ($i = 0; $i -lt $PartitionCount; $i++) {
            if ($null -ne $partitionWriters[$i]) {
                $partitionWriters[$i].Dispose()
                $partitionWriters[$i] = $null
            }
        }

        # Pass 2 — gather: process each partition independently
        for ($bucket = 0; $bucket -lt $PartitionCount; $bucket++) {
            $partPath = Join-Path $partitionDir "p$bucket.ndjson"
            if (-not (Test-Path -LiteralPath $partPath -PathType Leaf)) { continue }

            $rowsByIdentity = @{}
            foreach ($line in [System.IO.File]::ReadLines($partPath, [System.Text.UTF8Encoding]::new($false))) {
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                $row = $line | ConvertFrom-Json
                $identityKey = Get-VulnObservedWindowIdentityKey -Row $row
                if (-not $rowsByIdentity.ContainsKey($identityKey)) {
                    $rowsByIdentity[$identityKey] = [System.Collections.Generic.List[object]]::new()
                }
                $rowsByIdentity[$identityKey].Add($row)
            }

            foreach ($identityKey in @($rowsByIdentity.Keys)) {
                foreach ($mergedRow in @(Merge-VulnObservedWindowRows -Rows @($rowsByIdentity[$identityKey]) -AllowedGapDays $AllowedGapDays)) {
                    $mergedRowCount++
                    $mergedRow
                }
            }

            # Free partition memory before moving to next
            $rowsByIdentity.Clear()
            $rowsByIdentity = $null
            Remove-Item -LiteralPath $partPath -Force -ErrorAction SilentlyContinue
        }
    }
    finally {
        for ($i = 0; $i -lt $PartitionCount; $i++) {
            if ($null -ne $partitionWriters[$i]) {
                $partitionWriters[$i].Dispose()
            }
        }
        if (Test-Path -LiteralPath $partitionDir) {
            Remove-Item -Recurse -Force -LiteralPath $partitionDir -ErrorAction SilentlyContinue
        }
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
    Write-MergedVulnObservedWindowRows -Source { Read-VulnStoreRow -BasePath $normalizedStoreBasePath } -AllowedGapDays $AllowedGapDays
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
            Read-VulnStoreRow -BasePath $DataPath
            return
        }

        try {
            $observedWindowCachePath = Publish-VulnObservedWindowCache -BasePath $DataPath
            if (-not [string]::IsNullOrWhiteSpace($observedWindowCachePath) -and (Test-Path -LiteralPath $observedWindowCachePath -PathType Leaf)) {
                Write-Information ("  Using observed-window cache {0}" -f (Split-Path -Leaf $observedWindowCachePath)) -InformationAction Continue

                # Detect whether cache is in compact ref format (arrays starting with [)
                # or legacy full-record format (objects starting with {)
                $firstCacheLine = Get-GzipLine -Path $observedWindowCachePath | Select-Object -First 1
                if ($firstCacheLine -and $firstCacheLine.TrimStart().StartsWith('[')) {
                    # Content-store ref format — expand compact refs with the
                    # reduced streaming dictionary reader instead of loading the
                    # full JSON dictionary graph.
                    Read-VulnContentRefRows `
                        -DictionaryPath (Get-VulnContentDictionaryPath -BasePath $DataPath) `
                        -RefPaths @($observedWindowCachePath)
                }
                else {
                    Read-VulnNdjsonRecordsFromPath -Path $observedWindowCachePath
                }
                return
            }
        }
        catch {
            Write-Warning "  Observed-window cache build failed; falling back to live merge. $_"
        }

        $inputRowCount = 0
        $normalizedRowCount = 0
        Write-MergedVulnObservedWindowRows -Source { Read-VulnStoreRow -BasePath $DataPath } -InputRowCount ([ref]$inputRowCount) -OutputRowCount ([ref]$normalizedRowCount)

        if ($normalizedRowCount -ne $inputRowCount) {
            Write-Information ("  Collapsed {0} vulnerability observation row(s) into {1} normalized window(s)" -f $inputRowCount, $normalizedRowCount) -InformationAction Continue
        }
        return
    }

    throw "No canonical vulnerability store or content-store sidecars were found in '$DataPath'."
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
        [hashtable]$AdvancedHuntingDeviceUsers = @{},

        [Parameter(Mandatory = $false)]
        [hashtable]$AdvancedHuntingInventoryData = @{},

        [Parameter(Mandatory = $false)]
        [hashtable]$NvdCveData = @{},

        [Parameter(Mandatory = $false)]
        [switch]$SkipObservedWindowMerge,

        [Parameter(Mandatory = $false)]
        [string]$PayloadOutputPath,

        [Parameter(Mandatory = $false)]
        [switch]$ConsumeLookupsOnPayloadClose
    )

    Write-Information '  Normalizing data structure...' -InformationAction Continue
    Write-Information ("  Normalization inputs: {0} machine(s), {1} Advanced Hunting CVE(s), {2} device user row(s), {3} inventory tuple(s), {4} NVD CVE(s)" -f $Machines.Count, $AdvancedHuntingData.Count, $AdvancedHuntingDeviceUsers.Count, $AdvancedHuntingInventoryData.Count, $NvdCveData.Count) -InformationAction Continue
    Compress-NormalizationMachineLookup -Machines $Machines | Out-Null
    $context = Get-NormalizationContext
    $context.Machines = $Machines
    $context.AdvancedHuntingData = $AdvancedHuntingData
    $context.AdvancedHuntingDeviceUsers = $AdvancedHuntingDeviceUsers
    $context.AdvancedHuntingInventoryData = $AdvancedHuntingInventoryData
    $context.NvdCveData = $NvdCveData
    $lookups = $context.Lookups
    $tagIndex = $context.Indexes.tags

    $firstLastSwappedCount = 0
    $processedCount = 0
    $hasNoTags = $false
    $writerState = $null
    $writerCloseResult = $null
    $autoColumnDir = $null
    $lookupCountSummary = $null
    $consumeLookups = ($ConsumeLookupsOnPayloadClose -and -not [string]::IsNullOrWhiteSpace($PayloadOutputPath))

    # Auto-enable column-store format for better gzip compression when caller
    # has not explicitly specified a column directory.
    if ([string]::IsNullOrWhiteSpace($PayloadOutputPath) -and [string]::IsNullOrWhiteSpace($VulnColumnDirectoryPath)) {
        $autoColumnDir = Join-Path ([System.IO.Path]::GetTempPath()) ('vuln-cols-' + [System.Guid]::NewGuid().ToString('N'))
        $VulnColumnDirectoryPath = $autoColumnDir
        Write-Information '  Auto-using column-store format for payload compression.' -InformationAction Continue
    }

    $effectiveSkipObservedWindowMerge = ($SkipObservedWindowMerge -or (Test-IsSyntheticDataset -BasePath $DataPath))
    $contentStoreExists = Sync-VulnContentStoreSidecar -BasePath $DataPath
    $storeExists = ((Test-VulnStoreExistence -BasePath $DataPath) -or $contentStoreExists)

    if ($contentStoreExists) {
        # Content-store path: always use Invoke-ContentStoreNormalization.
        # For production data, merge refs first via observed-window cache.
        $mergedRefPaths = $null
        if (-not $effectiveSkipObservedWindowMerge) {
            Write-Information '  Content-store detected; building observed-window merge for production normalization...' -InformationAction Continue
            $observedWindowCachePath = Publish-VulnObservedWindowCache -BasePath $DataPath -AllowedGapDays 1
            if (-not [string]::IsNullOrWhiteSpace($observedWindowCachePath) -and (Test-Path -LiteralPath $observedWindowCachePath -PathType Leaf)) {
                Write-Information ("  Using merged ref cache {0}" -f (Split-Path -Leaf $observedWindowCachePath)) -InformationAction Continue
                $mergedRefPaths = @($observedWindowCachePath)
            }
        }
        else {
            Write-Information '  Content-store detected; using fast path (no merge).' -InformationAction Continue
        }
        $rawNormalizationResult = Invoke-ContentStoreNormalization -DataPath $DataPath -VulnOutputPath $VulnOutputPath -VulnColumnDirectoryPath $VulnColumnDirectoryPath -Context $context -Machines $Machines -AdvancedHuntingData $AdvancedHuntingData -AdvancedHuntingDeviceUsers $AdvancedHuntingDeviceUsers -AdvancedHuntingInventoryData $AdvancedHuntingInventoryData -NvdCveData $NvdCveData -MergedRefPaths $mergedRefPaths -PayloadOutputPath $PayloadOutputPath -ConsumeLookupsOnPayloadClose:$consumeLookups
        $processedCount = [int]$rawNormalizationResult.ProcessedCount
        $firstLastSwappedCount = [int]$rawNormalizationResult.FirstLastSwappedCount
        $hasNoTags = ($rawNormalizationResult.HasNoTags -eq $true)
        $lookupCountSummary = [PSCustomObject]@{
            DeviceCount = [int]$rawNormalizationResult.DeviceCount
            CveCount = [int]$rawNormalizationResult.CveCount
            SoftwareCount = [int]$rawNormalizationResult.SoftwareCount
            VendorCount = [int]$rawNormalizationResult.VendorCount
        }
        $writerCloseResult = [PSCustomObject]@{
            Mode = if ($rawNormalizationResult.PayloadPath) { 'payload' } elseif ($rawNormalizationResult.VulnColumnPaths) { 'column' } else { 'rows' }
            VulnsPath = $rawNormalizationResult.VulnsPath
            VulnColumnPaths = $rawNormalizationResult.VulnColumnPaths
            PayloadPath = $rawNormalizationResult.PayloadPath
        }
    }
    elseif ($effectiveSkipObservedWindowMerge -and $storeExists) {
        Write-Information '  Raw store detected; using raw store normalization fast path.' -InformationAction Continue
        $rawNormalizationResult = Invoke-RawStoreNormalization -DataPath $DataPath -VulnOutputPath $VulnOutputPath -VulnColumnDirectoryPath $VulnColumnDirectoryPath -Context $context -Machines $Machines -AdvancedHuntingData $AdvancedHuntingData -AdvancedHuntingDeviceUsers $AdvancedHuntingDeviceUsers -AdvancedHuntingInventoryData $AdvancedHuntingInventoryData -NvdCveData $NvdCveData -PayloadOutputPath $PayloadOutputPath -ConsumeLookupsOnPayloadClose:$consumeLookups
        $processedCount = [int]$rawNormalizationResult.ProcessedCount
        $firstLastSwappedCount = [int]$rawNormalizationResult.FirstLastSwappedCount
        $hasNoTags = ($rawNormalizationResult.HasNoTags -eq $true)
        $lookupCountSummary = [PSCustomObject]@{
            DeviceCount = [int]$rawNormalizationResult.DeviceCount
            CveCount = [int]$rawNormalizationResult.CveCount
            SoftwareCount = [int]$rawNormalizationResult.SoftwareCount
            VendorCount = [int]$rawNormalizationResult.VendorCount
        }
        $writerCloseResult = [PSCustomObject]@{
            Mode = if ($rawNormalizationResult.PayloadPath) { 'payload' } elseif ($rawNormalizationResult.VulnColumnPaths) { 'column' } else { 'rows' }
            VulnsPath = $rawNormalizationResult.VulnsPath
            VulnColumnPaths = $rawNormalizationResult.VulnColumnPaths
            PayloadPath = $rawNormalizationResult.PayloadPath
        }
    }
    else {
        try {
            $writerState = Open-NormalizedVulnWriter -VulnOutputPath $VulnOutputPath -VulnColumnDirectoryPath $VulnColumnDirectoryPath -PayloadOutputPath $PayloadOutputPath
            $compactRecord = [object[]]@(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1)

            # IMPORTANT: Use pipeline (| ForEach-Object) not foreach() to avoid
            # collecting all source rows into memory at once.
            Get-NormalizationSourceRows -DataPath $DataPath -SkipObservedWindowMerge:$effectiveSkipObservedWindowMerge | ForEach-Object {
                $v = $_
                if ($v.PSObject.Properties['IsOnboarded']?.Value -ne $true) { return }
                Write-NormalizedSourceRow `
                    -WriterState $writerState `
                    -Record $compactRecord `
                    -ProcessedCount ([ref]$processedCount) `
                    -DeviceId ([string]$v.DeviceId) `
                    -DeviceName $v.PSObject.Properties['DeviceName']?.Value `
                    -GroupName $v.PSObject.Properties['RbacGroupName']?.Value `
                    -OsPlatform $v.PSObject.Properties['OSPlatform']?.Value `
                    -OsVersion $v.PSObject.Properties['OSVersion']?.Value `
                    -MachineTags $v.PSObject.Properties['MachineTags']?.Value `
                    -SoftwareVendor $v.PSObject.Properties['SoftwareVendor']?.Value `
                    -SoftwareName $v.PSObject.Properties['SoftwareName']?.Value `
                    -RecommendationReference $v.PSObject.Properties['RecommendationReference']?.Value `
                    -CveId $v.CveId `
                    -CvssScore $v.PSObject.Properties['CvssScore']?.Value `
                    -SeverityLevel $v.PSObject.Properties['VulnerabilitySeverityLevel']?.Value `
                    -ExploitabilityLevel $v.PSObject.Properties['ExploitabilityLevel']?.Value `
                    -CveUrl $v.PSObject.Properties['CveBatchUrl']?.Value `
                    -CveBatchTitle $v.PSObject.Properties['CveBatchTitle']?.Value `
                    -RecommendedSecurityUpdate $v.PSObject.Properties['RecommendedSecurityUpdate']?.Value `
                    -RecommendedSecurityUpdateId $v.PSObject.Properties['RecommendedSecurityUpdateId']?.Value `
                    -RecommendedSecurityUpdateUrl $v.PSObject.Properties['RecommendedSecurityUpdateUrl']?.Value `
                    -SoftwareVersion $v.PSObject.Properties['SoftwareVersion']?.Value `
                    -DiskPaths @($v.PSObject.Properties['DiskPaths']?.Value) `
                    -RegistryPaths @($v.PSObject.Properties['RegistryPaths']?.Value) `
                    -SecurityUpdateAvailable $v.PSObject.Properties['SecurityUpdateAvailable']?.Value `
                    -Context $context `
                    -FirstSeenValue $v.PSObject.Properties['FirstSeenTimestamp']?.Value `
                    -LastSeenValue $v.PSObject.Properties['LastSeenTimestamp']?.Value `
                    -FirstLastSwappedCount ([ref]$firstLastSwappedCount)
            }

            Sync-NormalizedVulnWriter -WriterState $writerState
        }
        finally {
            if ($writerState) {
                if ($consumeLookups) {
                    $lookupCountSummary = Get-NormalizedLookupCountSummary -Lookups $context.Lookups
                }
                $writerCloseResult = Close-NormalizedVulnWriter -WriterState $writerState -Lookups $context.Lookups -ConsumeLookups:$consumeLookups
            }
        }
        $hasNoTags = $context.HasNoTags
    }

    Test-NormalizedWriterRowCount -WriterCloseResult $writerCloseResult -ExpectedRowCount $processedCount

    if ($null -eq $lookupCountSummary) {
        $lookupCountSummary = Get-NormalizedLookupCountSummary -Lookups $lookups
    }

    if ($processedCount -eq 0) {
        throw (New-NoOnboardedVulnerabilityMessage -DataPath $DataPath -SourceKind 'export files')
    }
    Write-Information "  Loaded $processedCount onboarded vulnerability records" -InformationAction Continue

    $deviceCount = [int]$lookupCountSummary.DeviceCount
    $cveCount = [int]$lookupCountSummary.CveCount
    $softwareCount = [int]$lookupCountSummary.SoftwareCount
    $vendorCount = [int]$lookupCountSummary.VendorCount

    $noTagsIdx = -1
    if (-not $consumeLookups) {
        $noTagsLabel = '(No Tags)'
        if ($hasNoTags -and -not $tagIndex.ContainsKey($noTagsLabel)) {
            $tagIndex[$noTagsLabel] = $lookups.tags.Count
            $lookups.tags.Add($noTagsLabel)
        }
        $noTagsIdx = if ($tagIndex.ContainsKey($noTagsLabel)) { $tagIndex[$noTagsLabel] } else { -1 }
    }

    Write-Information "  Normalized: $deviceCount devices, $cveCount CVEs, $softwareCount software, $vendorCount vendors" -InformationAction Continue
    if ($firstLastSwappedCount -gt 0) {
        Write-Warning "  Corrected $firstLastSwappedCount record(s) with FirstSeenTimestamp > LastSeenTimestamp"
    }

    $lookupRecord = $null
    if (-not $consumeLookups) {
        Update-NormalizedAffectedSoftwareLookup -Lookups $lookups
        $lookupRecord = ConvertTo-NormalizedLookupRecord -Lookups $lookups -NoTagsIdx $noTagsIdx
    }

    return @{
        Lookups = $lookupRecord
        LookupsConsumed = $consumeLookups
        DeviceCount = $deviceCount
        CveCount = $cveCount
        SoftwareCount = $softwareCount
        VendorCount = $vendorCount
        Quality = [PSCustomObject]@{
            FirstLastSwappedCount = $firstLastSwappedCount
        }
        VulnCount = $processedCount
        VulnsPath = $writerCloseResult.VulnsPath
        VulnColumnPaths = $writerCloseResult.VulnColumnPaths
        PayloadPath = $writerCloseResult.PayloadPath
    }
}
