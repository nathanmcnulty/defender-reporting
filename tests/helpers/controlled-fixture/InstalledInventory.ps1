#Requires -Version 7.6
# Read-only inventory verification. Builds, process launches and installations stay with callers.
function Read-InstalledInventory {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$Sha256)
    if ($Sha256 -cnotmatch '^[a-f0-9]{64}\z') { throw 'Invalid inventory digest.' }
    $file = [IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if ($file.Length -lt 2 -or $file.Length -gt 16MB) { throw 'Invalid inventory size.' }
        $bytes = [byte[]]::new([int]$file.Length); $file.ReadExactly($bytes,0,$bytes.Length)
    } finally { $file.Dispose() }
    if ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant() -cne $Sha256) { throw 'Inventory digest changed.' }
    $text = [Text.UTF8Encoding]::new($false,$true).GetString($bytes)
    $document = [Text.Json.JsonDocument]::Parse($text,[Text.Json.JsonDocumentOptions]@{ MaxDepth = 16 })
    try {
        if ($document.RootElement.ValueKind -ne [Text.Json.JsonValueKind]::Object) { throw 'Inventory root must be an object.' }
        $pending = [Collections.Generic.Stack[Text.Json.JsonElement]]::new(); $pending.Push($document.RootElement)
        while ($pending.Count) {
            $element = $pending.Pop()
            if ($element.ValueKind -eq [Text.Json.JsonValueKind]::Object) {
                $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                foreach ($property in $element.EnumerateObject()) {
                    if (-not $names.Add($property.Name)) { throw 'Duplicate inventory key.' }
                    $pending.Push($property.Value)
                }
            } elseif ($element.ValueKind -eq [Text.Json.JsonValueKind]::Array) {
                foreach ($value in $element.EnumerateArray()) { $pending.Push($value) }
            }
        }
    } finally { $document.Dispose() }
    $text | ConvertFrom-Json -AsHashtable -Depth 16 -DateKind String
}

function Assert-InstalledInventory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][Collections.IDictionary]$Manifest,
        [Parameter(Mandatory)][ValidateSet('toolchain','powershell')][string]$Kind,
        [string]$Executable,
        [string]$ExecutableSha256,
        [string]$Version
    )
    function Assert-InventoryCondition([bool]$Condition,[string]$Message) { if (-not $Condition) { throw $Message } }
    function Get-InventoryRoot([object]$Value) {
        Assert-InventoryCondition ($Value -is [string] -and [IO.Path]::IsPathFullyQualified($Value) -and $Value -notmatch '[\x00-\x1f]') 'Absolute inventory path required.'
        $full = [IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetFullPath($Value))
        $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
        Assert-InventoryCondition ($item.PSIsContainer) 'Inventory root is not a directory.'
        # Reject linked ancestors as well as the root itself; lexical path checks alone are insufficient.
        for ($directory = [IO.DirectoryInfo]::new($full); $null -ne $directory; $directory = $directory.Parent) {
            Assert-InventoryCondition (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'Linked inventory root or ancestor.'
        }
        $full
    }
    function Assert-InventoryFile([string]$Root,[object]$Files) {
        Assert-InventoryCondition ($Files -is [array] -and $Files.Count -gt 0) 'Inventory files must be a nonempty array.'
        $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($entry in $Files) {
            Assert-InventoryCondition ($entry -is [Collections.IDictionary] -and $entry.Count -eq 3 -and @($entry.Keys | Where-Object { $_ -cnotin @('path','bytes','sha256') }).Count -eq 0) 'Invalid inventory file fields.'
            $relative = $entry.path
            Assert-InventoryCondition ($relative -is [string] -and $relative -cmatch '^[^\\:\x00-\x1f]+\z' -and -not [IO.Path]::IsPathRooted($relative)) 'Invalid inventory relative path.'
            $parts = $relative.Split('/')
            Assert-InventoryCondition (@($parts | Where-Object { $_ -in @('','.','..') -or $_.EndsWith('.') -or $_.EndsWith(' ') }).Count -eq 0 -and $names.Add($relative)) 'Duplicate or noncanonical inventory path.'
            Assert-InventoryCondition (($entry.bytes -is [int] -or $entry.bytes -is [long]) -and $entry.bytes -ge 0 -and $entry.sha256 -is [string] -and $entry.sha256 -cmatch '^[a-f0-9]{64}\z') 'Invalid inventory file digest or size.'
        }
        $entries = @(Get-ChildItem -LiteralPath $Root -Recurse -Force -ErrorAction Stop)
        Assert-InventoryCondition (@($entries | Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 }).Count -eq 0) 'Linked inventory entry.'
        $actual = @($entries | Where-Object { -not $_.PSIsContainer } | ForEach-Object { [IO.Path]::GetRelativePath($Root,$_.FullName).Replace('\','/') } | Sort-Object -CaseSensitive)
        $expected = @($Files.path | Sort-Object -CaseSensitive)
        Assert-InventoryCondition ($actual.Count -eq $expected.Count -and @(Compare-Object $expected $actual -CaseSensitive).Count -eq 0) 'Installed inventory file set changed.'
        foreach ($entry in $Files) {
            $path = Join-Path $Root $entry.path
            Assert-InventoryCondition ((Get-Item -LiteralPath $path -Force -ErrorAction Stop).Length -eq $entry.bytes -and (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() -ceq $entry.sha256) 'Installed inventory file bytes changed.'
        }
    }
    $required = if ($Kind -ceq 'toolchain') { @('schema','kind','sdkVersion','runtimeVersion','dotnetRoot','dotnet','dotnetSha256','runtimeDirectory','groups') } else { @('schema','kind','root','executableSha256','version','files') }
    $metadata = if ($Kind -ceq 'toolchain') { @('meaning') } else { @('fileVersion','bundledCoreRuntime') }
    Assert-InventoryCondition (@($Manifest.Keys | Where-Object { $_ -cnotin ($required + $metadata) }).Count -eq 0 -and @($required | Where-Object { $_ -cnotin $Manifest.Keys }).Count -eq 0) 'Invalid inventory top-level fields.'
    foreach ($key in $metadata) { if ($Manifest.Contains($key)) { Assert-InventoryCondition ($Manifest[$key] -is [string] -and $Manifest[$key].Length -gt 0) 'Invalid inventory metadata.' } }
    Assert-InventoryCondition ($Manifest.schema -is [int] -or $Manifest.schema -is [long]) 'Inventory schema type invalid.'
    Assert-InventoryCondition ($Manifest.schema -eq 1 -and $Manifest.kind -is [string] -and $Manifest.kind -ceq $Kind) 'Inventory kind/schema mismatch.'
    if ($Kind -ceq 'toolchain') {
        Assert-InventoryCondition ($Manifest.sdkVersion -is [string] -and $Manifest.runtimeVersion -is [string] -and $Manifest.sdkVersion -cmatch '^10\.0\.[1-9][0-9]*\z' -and $Manifest.runtimeVersion -cmatch '^10\.0\.[1-9][0-9]*\z') 'Toolchain versions invalid.'
        $root = Get-InventoryRoot $Manifest.dotnetRoot
        $expectedRoots = [ordered]@{
            sdk = Join-Path $root ('sdk/'+$Manifest.sdkVersion)
            reference = Join-Path $root ('packs/Microsoft.NETCore.App.Ref/'+$Manifest.runtimeVersion)
            apphost = Join-Path $root ('packs/Microsoft.NETCore.App.Host.win-x64/'+$Manifest.runtimeVersion)
            runtime = Join-Path $root ('shared/Microsoft.NETCore.App/'+$Manifest.runtimeVersion)
            hostfxr = Join-Path $root 'host/fxr'
        }
        Assert-InventoryCondition ($Manifest.dotnet -is [string] -and [IO.Path]::IsPathFullyQualified($Manifest.dotnet) -and [IO.Path]::GetFullPath($Manifest.dotnet) -ceq (Join-Path $root 'dotnet.exe') -and $Manifest.dotnetSha256 -is [string] -and $Manifest.dotnetSha256 -cmatch '^[a-f0-9]{64}\z') 'Toolchain executable/root mismatch.'
        Assert-InventoryCondition ($Manifest.runtimeDirectory -is [string] -and [IO.Path]::IsPathFullyQualified($Manifest.runtimeDirectory) -and [IO.Path]::GetFullPath($Manifest.runtimeDirectory) -ceq $expectedRoots.runtime) 'Toolchain runtime root mismatch.'
        Assert-InventoryCondition ($Manifest.groups -is [array] -and $Manifest.groups.Count -eq 5) 'Complete five-group toolchain inventory required.'
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($group in $Manifest.groups) {
            Assert-InventoryCondition ($group -is [Collections.IDictionary] -and $group.Count -eq 3 -and @($group.Keys | Where-Object { $_ -cnotin @('id','root','files') }).Count -eq 0 -and $group.id -is [string] -and $group.id -cin $expectedRoots.Keys -and $seen.Add($group.id)) 'Duplicate, unknown or malformed toolchain group.'
            $groupRoot = Get-InventoryRoot $group.root
            Assert-InventoryCondition ($groupRoot -ceq $expectedRoots[$group.id]) 'Toolchain group root mismatch.'
        }
        foreach ($group in $Manifest.groups) { Assert-InventoryFile (Get-InventoryRoot $group.root) $group.files }
        Assert-InventoryCondition (((Get-Item -LiteralPath $Manifest.dotnet -Force -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'Linked toolchain executable.'
        Assert-InventoryCondition ((Get-FileHash -LiteralPath $Manifest.dotnet -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() -ceq $Manifest.dotnetSha256) 'Toolchain executable changed.'
    } else {
        Assert-InventoryCondition (-not $Manifest.Contains('groups') -and $ExecutableSha256 -cmatch '^[a-f0-9]{64}\z' -and $Version -cmatch '^\d+\.\d+\.\d+\z' -and [version]$Version -ge [version]'7.6' -and [IO.Path]::IsPathFullyQualified($Executable)) 'Independent PowerShell identity required.'
        $root = Get-InventoryRoot $Manifest.root
        Assert-InventoryCondition ($root -ceq [IO.Path]::GetFullPath([IO.Path]::GetDirectoryName($Executable)) -and $Manifest.version -is [string] -and $Manifest.version -ceq $Version -and $Manifest.executableSha256 -is [string] -and $Manifest.executableSha256 -ceq $ExecutableSha256) 'PowerShell root/runtime binding mismatch.'
        Assert-InventoryFile $root $Manifest.files
        Assert-InventoryCondition ((Get-FileHash -LiteralPath $Executable -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() -ceq $ExecutableSha256) 'PowerShell executable changed.'
    }
}
