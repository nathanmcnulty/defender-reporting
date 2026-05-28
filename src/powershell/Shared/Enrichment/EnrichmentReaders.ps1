# Shared enrichment readers used by dashboard generation, validation, and Azure
# packaging outputs.

function Resolve-AdvancedHuntingBundleSourceFileList {
    [CmdletBinding()]
    [OutputType([System.IO.FileInfo[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $currentPath = Get-AdvancedHuntingCurrentPath -BasePath $Path
    $legacyCurrentPath = Get-LegacyCanonicalPath -Path $currentPath

    if ((-not (Test-Path -LiteralPath $currentPath -PathType Leaf)) -and (Test-Path -LiteralPath $legacyCurrentPath -PathType Leaf)) {
        Assert-LegacyMigrationAllowed -FeatureName 'Advanced Hunting snapshot compatibility' -LegacyPaths @($legacyCurrentPath)
        $currentPath = $legacyCurrentPath
    }

    if (Test-Path -LiteralPath $currentPath -PathType Leaf) {
        return @((Get-Item -LiteralPath $currentPath))
    }

    $legacyFiles = @(Get-ChildItem -Path $Path -Filter 'AdvancedHunting_*.json' -File -ErrorAction SilentlyContinue |
        Where-Object { Test-IsLegacyAdvancedHuntingSnapshotFileName -Name $_.Name } |
        Sort-Object Name -Descending)
    Assert-LegacyMigrationAllowed -FeatureName 'Advanced Hunting snapshot compatibility' -LegacyPaths @($legacyFiles | ForEach-Object { $_.FullName })
    return @($legacyFiles)
}

function ConvertTo-AdvancedHuntingBundleStringArray {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) {
        return ,([string[]]@())
    }

    if ($Value -is [string]) {
        if ([string]::IsNullOrWhiteSpace($Value)) {
            return ,([string[]]@())
        }

        return ,([string[]]@($Value))
    }

    if ($Value -is [string[]]) {
        $requiresFiltering = $false
        foreach ($text in $Value) {
            if ([string]::IsNullOrWhiteSpace($text)) {
                $requiresFiltering = $true
                break
            }
        }

        if (-not $requiresFiltering) {
            return ,$Value
        }

        $values = [System.Collections.Generic.List[string]]::new($Value.Length)
        foreach ($item in $Value) {
            $text = [string]$item
            if (-not [string]::IsNullOrWhiteSpace($text)) {
                $values.Add($text)
            }
        }

        return ,([string[]]$values.ToArray())
    }

    $values = $null
    if ($Value -is [System.Array]) {
        $values = [System.Collections.Generic.List[string]]::new($Value.Length)
    }
    elseif ($Value -is [System.Collections.ICollection]) {
        $values = [System.Collections.Generic.List[string]]::new($Value.Count)
    }
    else {
        $values = [System.Collections.Generic.List[string]]::new()
    }

    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        foreach ($item in $Value) {
            if ($null -eq $item) { continue }
            $text = [string]$item
            if (-not [string]::IsNullOrWhiteSpace($text)) {
                $values.Add($text)
            }
        }
    }
    else {
        $text = [string]$Value
        if (-not [string]::IsNullOrWhiteSpace($text)) {
            $values.Add($text)
        }
    }

    return ,([string[]]$values.ToArray())
}

function ConvertTo-AdvancedHuntingBundleDescriptionValue {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [string]) {
        return $Value
    }

    $parts = ConvertTo-AdvancedHuntingBundleStringArray -Value $Value
    if ($parts.Count -eq 0) {
        return $null
    }

    return ($parts -join "`n")
}

function ConvertTo-AdvancedHuntingBundleNullableBoolean {
    [CmdletBinding()]
    [OutputType([Nullable[bool]])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [bool]) {
        return $Value
    }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }

    switch -Regex ($text.Trim().ToLowerInvariant()) {
        '^(true|1|yes)$' { return $true }
        '^(false|0|no)$' { return $false }
    }

    return $null
}

function Add-AdvancedHuntingBundleLoggedOnUserValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Value,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]]$Values,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.HashSet[string]]$Seen
    )

    if ($null -eq $Value) {
        return
    }

    if ($Value -is [string]) {
        $text = $Value.Trim()
        if ([string]::IsNullOrWhiteSpace($text)) {
            return
        }

        if ((($text.StartsWith('[') -and $text.EndsWith(']')) -or ($text.StartsWith('{') -and $text.EndsWith('}')))) {
            try {
                $parsedValue = $text | ConvertFrom-Json -Depth 20
                Add-AdvancedHuntingBundleLoggedOnUserValue -Value $parsedValue -Values $Values -Seen $Seen
                return
            }
            catch {
                Write-Verbose ("Falling back to raw LoggedOnUsers text after JSON parse failed: {0}" -f $_.Exception.Message)
            }
        }

        if ($Seen.Add($text)) {
            $Values.Add($text)
        }
        return
    }

    if ($Value -is [pscustomobject] -or $Value -is [System.Collections.IDictionary]) {
        $propertyBag = $Value.PSObject.Properties
        $upn = [string]$propertyBag['UserPrincipalName']?.Value
        $domainName = [string]$propertyBag['DomainName']?.Value
        $accountName = [string]$propertyBag['AccountName']?.Value
        $userName = [string]$propertyBag['UserName']?.Value
        $displayName = [string]$propertyBag['Name']?.Value

        $resolvedName = $null
        if (-not [string]::IsNullOrWhiteSpace($upn)) {
            $resolvedName = $upn.Trim()
        }
        elseif (-not [string]::IsNullOrWhiteSpace($accountName)) {
            $resolvedName = if (-not [string]::IsNullOrWhiteSpace($domainName)) {
                $domainName.Trim() + '\' + $accountName.Trim()
            }
            else {
                $accountName.Trim()
            }
        }
        elseif (-not [string]::IsNullOrWhiteSpace($userName)) {
            $resolvedName = if (-not [string]::IsNullOrWhiteSpace($domainName)) {
                $domainName.Trim() + '\' + $userName.Trim()
            }
            else {
                $userName.Trim()
            }
        }
        elseif (-not [string]::IsNullOrWhiteSpace($displayName)) {
            $resolvedName = $displayName.Trim()
        }

        if (-not [string]::IsNullOrWhiteSpace($resolvedName)) {
            if ($Seen.Add($resolvedName)) {
                $Values.Add($resolvedName)
            }
            return
        }

        foreach ($property in $propertyBag) {
            Add-AdvancedHuntingBundleLoggedOnUserValue -Value $property.Value -Values $Values -Seen $Seen
        }
        return
    }

    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        foreach ($item in $Value) {
            Add-AdvancedHuntingBundleLoggedOnUserValue -Value $item -Values $Values -Seen $Seen
        }
        return
    }

    $fallbackText = [string]$Value
    if (-not [string]::IsNullOrWhiteSpace($fallbackText) -and $Seen.Add($fallbackText)) {
        $Values.Add($fallbackText)
    }
}

function ConvertTo-AdvancedHuntingBundleLoggedOnUserList {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Value
    )

    $values = [System.Collections.Generic.List[string]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    Add-AdvancedHuntingBundleLoggedOnUserValue -Value $Value -Values $values -Seen $seen
    return [string[]]$values.ToArray()
}

function Read-AdvancedHuntingBundle {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeDeviceUsers,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeInventoryData
    )

    $includeDeviceUsersRequested = [bool]$IncludeDeviceUsers
    $includeInventoryDataRequested = [bool]$IncludeInventoryData

    return Invoke-WithStoreLock -BasePath $Path -StoreName 'advancedhunting' -ScriptBlock {
        Restore-StoreTransaction -BasePath $Path -StoreName 'advancedhunting'

        Write-Information "Reading Advanced Hunting bundle data from $Path..." -InformationAction Continue

        $ahData = @{}
        $deviceUsers = @{}
        $inventoryData = @{}
        $parseErrors = 0
        $sourceFiles = @(Resolve-AdvancedHuntingBundleSourceFileList -Path $Path)

        if ($sourceFiles.Count -eq 0) {
            Write-Information '  No Advanced Hunting data files found. Bundle outputs will be empty.' -InformationAction Continue
            return [PSCustomObject]@{
                AdvancedHuntingData = @{}
                DeviceUsers = @{}
                InventoryData = @{}
            }
        }

        if ($sourceFiles.Count -eq 1) {
            Write-Information "  Using $($sourceFiles[0].Name)" -InformationAction Continue
        }
        else {
            Write-Information "  Found $($sourceFiles.Count) legacy Advanced Hunting file(s)" -InformationAction Continue
        }

        foreach ($file in $sourceFiles) {
            Write-Information "  Processing $($file.Name)..." -InformationAction Continue
            foreach ($record in Read-AdvancedHuntingRecordsFromFile -Path $file.FullName) {
                try {
                    $recordType = Get-AdvancedHuntingRecordType -Record $record

                    if ($includeInventoryDataRequested -and $recordType -eq 'Inventory') {
                        $inventoryKey = Get-AdvancedHuntingInventoryMatchKey `
                            -DeviceId ([string]$record.PSObject.Properties['DeviceId']?.Value) `
                            -SoftwareVendor ([string]$record.PSObject.Properties['SoftwareVendor']?.Value) `
                            -SoftwareName ([string]$record.PSObject.Properties['SoftwareName']?.Value) `
                            -SoftwareVersion ([string]$record.PSObject.Properties['SoftwareVersion']?.Value)
                        if ([string]::IsNullOrWhiteSpace($inventoryKey) -or $inventoryData.ContainsKey($inventoryKey)) {
                            continue
                        }

                        $productCodeCpe = [string]$record.PSObject.Properties['ProductCodeCpe']?.Value
                        $endOfSupportStatus = [string]$record.PSObject.Properties['EndOfSupportStatus']?.Value
                        $endOfSupportDate = Convert-ToYmdDate -DateValue $record.PSObject.Properties['EndOfSupportDate']?.Value

                        if ([string]::IsNullOrWhiteSpace($productCodeCpe) -and [string]::IsNullOrWhiteSpace($endOfSupportStatus) -and [string]::IsNullOrWhiteSpace($endOfSupportDate)) {
                            continue
                        }

                        $inventoryData[$inventoryKey] = @{
                            ProductCodeCpe = if ([string]::IsNullOrWhiteSpace($productCodeCpe)) { $null } else { $productCodeCpe }
                            EndOfSupportStatus = if ([string]::IsNullOrWhiteSpace($endOfSupportStatus)) { $null } else { $endOfSupportStatus }
                            EndOfSupportDate = $endOfSupportDate
                        }
                        continue
                    }

                    if ($includeDeviceUsersRequested -and $recordType -eq 'DeviceUsers') {
                        $deviceId = [string]$record.PSObject.Properties['DeviceId']?.Value
                        if ([string]::IsNullOrWhiteSpace($deviceId) -or $deviceUsers.ContainsKey($deviceId)) {
                            continue
                        }

                        $loggedOnUsers = ConvertTo-AdvancedHuntingBundleLoggedOnUserList -Value $record.PSObject.Properties['LoggedOnUsers']?.Value
                        if ($loggedOnUsers.Count -gt 0) {
                            $deviceUsers[$deviceId] = $loggedOnUsers
                        }
                        continue
                    }

                    $cveId = [string]$record.PSObject.Properties['CveId']?.Value
                    if (-not [string]::IsNullOrWhiteSpace($cveId) -and -not $ahData.ContainsKey($cveId)) {
                        $pdRaw = $record.PSObject.Properties['PublishedDate']?.Value
                        $rawDescription = $record.PSObject.Properties['VulnerabilityDescription']?.Value
                        $rawAffectedSoftware = $record.PSObject.Properties['AffectedSoftware']?.Value
                        $affectedSoftware = ConvertTo-AdvancedHuntingBundleStringArray -Value $rawAffectedSoftware
                        $ahData[$cveId] = @{
                            PublishedDate = Convert-ToYmdDate -DateValue $pdRaw
                            VulnerabilityDescription = ConvertTo-AdvancedHuntingBundleDescriptionValue -Value $rawDescription
                            EpssScore = $record.PSObject.Properties['EpssScore']?.Value
                            AffectedSoftware = if ($affectedSoftware.Count -gt 0) { $affectedSoftware } else { $null }
                            IsExploitAvailable = ConvertTo-AdvancedHuntingBundleNullableBoolean -Value $record.PSObject.Properties['IsExploitAvailable']?.Value
                        }
                    }
                }
                catch {
                    $parseErrors++
                    if ($parseErrors -le 5) {
                        Write-Warning "Failed to process Advanced Hunting bundle record in $($file.Name): $_"
                    }
                }
            }
        }

        if ($parseErrors -gt 0) {
            Write-Warning "Total bundle parse errors: $parseErrors"
        }

        Write-Information "  Bundle loaded $($ahData.Count) unique CVE(s)" -InformationAction Continue
        if ($IncludeDeviceUsers) {
            Write-Information "  Bundle loaded $($deviceUsers.Count) device-user record(s)" -InformationAction Continue
        }
        if ($IncludeInventoryData) {
            Write-Information "  Bundle loaded $($inventoryData.Count) inventory tuple(s)" -InformationAction Continue
        }

        return [PSCustomObject]@{
            AdvancedHuntingData = $ahData
            DeviceUsers = $deviceUsers
            InventoryData = $inventoryData
        }
    }
}

function Read-AdvancedHuntingData {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    function ConvertTo-AdvancedHuntingStringArray {
        [CmdletBinding()]
        [OutputType([string[]])]
        param(
            [Parameter(Mandatory = $false)]
            [AllowNull()]
            $Value
        )

        return ,(ConvertTo-AdvancedHuntingBundleStringArray -Value $Value)
    }

    function ConvertTo-AdvancedHuntingDescriptionValue {
        [CmdletBinding()]
        [OutputType([string])]
        param(
            [Parameter(Mandatory = $false)]
            [AllowNull()]
            $Value
        )

        if ($null -eq $Value) {
            return $null
        }

        if ($Value -is [string]) {
            return $Value
        }

        $parts = ConvertTo-AdvancedHuntingStringArray -Value $Value
        if ($parts.Count -eq 0) {
            return $null
        }

        return ($parts -join "`n")
    }

    function ConvertTo-AdvancedHuntingNullableBoolean {
        [CmdletBinding()]
        [OutputType([Nullable[bool]])]
        param(
            [Parameter(Mandatory = $false)]
            [AllowNull()]
            $Value
        )

        if ($null -eq $Value) {
            return $null
        }

        if ($Value -is [bool]) {
            return $Value
        }

        $text = [string]$Value
        if ([string]::IsNullOrWhiteSpace($text)) {
            return $null
        }

        switch -Regex ($text.Trim().ToLowerInvariant()) {
            '^(true|1|yes)$' { return $true }
            '^(false|0|no)$' { return $false }
        }

        return $null
    }

    return Invoke-WithStoreLock -BasePath $Path -StoreName 'advancedhunting' -ScriptBlock {
        Restore-StoreTransaction -BasePath $Path -StoreName 'advancedhunting'

        Write-Information "Reading Advanced Hunting data from $Path..." -InformationAction Continue

        $ahData = @{}
        $parseErrors = 0
        $sourceFiles = @(Resolve-AdvancedHuntingBundleSourceFileList -Path $Path)
        if ($sourceFiles.Count -eq 0) {
            Write-Warning 'No Advanced Hunting data files found. CVE enrichment will be skipped.'
            return @{}
        }

        if ($sourceFiles.Count -eq 1) {
            Write-Information "  Using $($sourceFiles[0].Name)" -InformationAction Continue
        }
        else {
            Write-Information "  Found $($sourceFiles.Count) legacy Advanced Hunting file(s)" -InformationAction Continue
        }

        foreach ($file in $sourceFiles) {
            Write-Information "  Processing $($file.Name)..." -InformationAction Continue
            foreach ($record in Read-AdvancedHuntingRecordsFromFile -Path $file.FullName) {
                try {
                    $cveId = [string]$record.PSObject.Properties['CveId']?.Value
                    if (-not [string]::IsNullOrWhiteSpace($cveId) -and -not $ahData.ContainsKey($cveId)) {
                        $pdRaw = $record.PSObject.Properties['PublishedDate']?.Value
                        $rawDescription = $record.PSObject.Properties['VulnerabilityDescription']?.Value
                        $rawAffectedSoftware = $record.PSObject.Properties['AffectedSoftware']?.Value
                        $affectedSoftware = ConvertTo-AdvancedHuntingStringArray -Value $rawAffectedSoftware
                        $ahData[$cveId] = @{
                            PublishedDate = Convert-ToYmdDate -DateValue $pdRaw
                            VulnerabilityDescription = ConvertTo-AdvancedHuntingDescriptionValue -Value $rawDescription
                            EpssScore = $record.PSObject.Properties['EpssScore']?.Value
                            AffectedSoftware = if ($affectedSoftware.Count -gt 0) { $affectedSoftware } else { $null }
                            IsExploitAvailable = ConvertTo-AdvancedHuntingNullableBoolean -Value $record.PSObject.Properties['IsExploitAvailable']?.Value
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

function Read-AdvancedHuntingInventoryData {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return Invoke-WithStoreLock -BasePath $Path -StoreName 'advancedhunting' -ScriptBlock {
        Restore-StoreTransaction -BasePath $Path -StoreName 'advancedhunting'

        Write-Information "Reading Advanced Hunting software inventory data from $Path..." -InformationAction Continue

        $inventoryData = @{}
        $parseErrors = 0
        $sourceFiles = @(Resolve-AdvancedHuntingBundleSourceFileList -Path $Path)
        if ($sourceFiles.Count -eq 0) {
            Write-Information '  No Advanced Hunting software inventory data files found.' -InformationAction Continue
            return @{}
        }

        if ($sourceFiles.Count -eq 1) {
            Write-Information "  Using $($sourceFiles[0].Name)" -InformationAction Continue
        }
        else {
            Write-Information "  Found $($sourceFiles.Count) legacy Advanced Hunting file(s)" -InformationAction Continue
        }

        foreach ($file in $sourceFiles) {
            Write-Information "  Processing $($file.Name)..." -InformationAction Continue
            foreach ($record in Read-AdvancedHuntingRecordsFromFile -Path $file.FullName) {
                try {
                    if ((Get-AdvancedHuntingRecordType -Record $record) -ne 'Inventory') {
                        continue
                    }

                    $inventoryKey = Get-AdvancedHuntingInventoryMatchKey `
                        -DeviceId ([string]$record.PSObject.Properties['DeviceId']?.Value) `
                        -SoftwareVendor ([string]$record.PSObject.Properties['SoftwareVendor']?.Value) `
                        -SoftwareName ([string]$record.PSObject.Properties['SoftwareName']?.Value) `
                        -SoftwareVersion ([string]$record.PSObject.Properties['SoftwareVersion']?.Value)
                    if ([string]::IsNullOrWhiteSpace($inventoryKey) -or $inventoryData.ContainsKey($inventoryKey)) {
                        continue
                    }

                    $productCodeCpe = [string]$record.PSObject.Properties['ProductCodeCpe']?.Value
                    $endOfSupportStatus = [string]$record.PSObject.Properties['EndOfSupportStatus']?.Value
                    $endOfSupportDate = Convert-ToYmdDate -DateValue $record.PSObject.Properties['EndOfSupportDate']?.Value

                    if ([string]::IsNullOrWhiteSpace($productCodeCpe) -and [string]::IsNullOrWhiteSpace($endOfSupportStatus) -and [string]::IsNullOrWhiteSpace($endOfSupportDate)) {
                        continue
                    }

                    $inventoryData[$inventoryKey] = @{
                        ProductCodeCpe = if ([string]::IsNullOrWhiteSpace($productCodeCpe)) { $null } else { $productCodeCpe }
                        EndOfSupportStatus = if ([string]::IsNullOrWhiteSpace($endOfSupportStatus)) { $null } else { $endOfSupportStatus }
                        EndOfSupportDate = $endOfSupportDate
                    }
                }
                catch {
                    $parseErrors++
                    if ($parseErrors -le 5) {
                        Write-Warning "Failed to process Advanced Hunting inventory record in $($file.Name): $_"
                    }
                }
            }
        }

        if ($parseErrors -gt 0) {
            Write-Warning "Total parse errors: $parseErrors"
        }

        Write-Information "  Loaded software inventory data for $($inventoryData.Count) device/software tuple(s)" -InformationAction Continue
        return $inventoryData
    }
}

function Read-AdvancedHuntingDeviceUserMap {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return Invoke-WithStoreLock -BasePath $Path -StoreName 'advancedhunting' -ScriptBlock {
        Restore-StoreTransaction -BasePath $Path -StoreName 'advancedhunting'

        Write-Information "Reading Advanced Hunting device-user data from $Path..." -InformationAction Continue

        $deviceUsers = @{}
        $parseErrors = 0
        $sourceFiles = @(Resolve-AdvancedHuntingBundleSourceFileList -Path $Path)
        if ($sourceFiles.Count -eq 0) {
            Write-Information '  No Advanced Hunting device-user data files found.' -InformationAction Continue
            return @{}
        }

        if ($sourceFiles.Count -eq 1) {
            Write-Information "  Using $($sourceFiles[0].Name)" -InformationAction Continue
        }
        else {
            Write-Information "  Found $($sourceFiles.Count) legacy Advanced Hunting file(s)" -InformationAction Continue
        }

        foreach ($file in $sourceFiles) {
            Write-Information "  Processing $($file.Name)..." -InformationAction Continue
            foreach ($record in Read-AdvancedHuntingRecordsFromFile -Path $file.FullName) {
                try {
                    if ((Get-AdvancedHuntingRecordType -Record $record) -ne 'DeviceUsers') {
                        continue
                    }

                    $deviceId = [string]$record.PSObject.Properties['DeviceId']?.Value
                    if ([string]::IsNullOrWhiteSpace($deviceId) -or $deviceUsers.ContainsKey($deviceId)) {
                        continue
                    }

                    $loggedOnUsers = @(ConvertTo-AdvancedHuntingBundleLoggedOnUserList -Value $record.PSObject.Properties['LoggedOnUsers']?.Value)
                    if ($loggedOnUsers.Count -gt 0) {
                        $deviceUsers[$deviceId] = @($loggedOnUsers)
                    }
                }
                catch {
                    $parseErrors++
                    if ($parseErrors -le 5) {
                        Write-Warning "Failed to process Advanced Hunting device-user record in $($file.Name): $_"
                    }
                }
            }
        }

        if ($parseErrors -gt 0) {
            Write-Warning "Total parse errors: $parseErrors"
        }

        Write-Information "  Loaded logged-on user data for $($deviceUsers.Count) device(s)" -InformationAction Continue
        return $deviceUsers
    }
}

function Read-NvdCveData {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    function ConvertTo-NvdStringArray {
        [CmdletBinding()]
        [OutputType([string[]])]
        param(
            [Parameter(Mandatory = $false)]
            [AllowNull()]
            $Value
        )

        if ($null -eq $Value) {
            return @()
        }

        $values = [System.Collections.Generic.List[string]]::new()
        if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
            foreach ($item in $Value) {
                if ($null -eq $item) { continue }
                $text = [string]$item
                if (-not [string]::IsNullOrWhiteSpace($text)) {
                    $values.Add($text)
                }
            }
        }
        else {
            $text = [string]$Value
            if (-not [string]::IsNullOrWhiteSpace($text)) {
                $values.Add($text)
            }
        }

        return [string[]]$values.ToArray()
    }

    function ConvertTo-NvdDescriptionValue {
        [CmdletBinding()]
        [OutputType([string])]
        param(
            [Parameter(Mandatory = $false)]
            [AllowNull()]
            $Value
        )

        $parts = @(ConvertTo-NvdStringArray -Value $Value)
        if ($parts.Count -eq 0) {
            return $null
        }

        return ($parts -join "`n")
    }

    return Invoke-WithStoreLock -BasePath $Path -StoreName 'nvdcve' -ScriptBlock {
        Restore-StoreTransaction -BasePath $Path -StoreName 'nvdcve'

        $currentPath = Get-NvdCveCurrentPath -BasePath $Path
        if (-not (Test-Path -LiteralPath $currentPath -PathType Leaf)) {
            Write-Information "No NVD CVE cache found at $currentPath. NVD enrichment will be skipped." -InformationAction Continue
            return @{}
        }

        Write-Information "Reading NVD CVE data from $currentPath..." -InformationAction Continue

        $rawJson = Read-GzipTextFile -Path $currentPath
        if ([string]::IsNullOrWhiteSpace($rawJson)) {
            return @{}
        }

        try {
            $document = $rawJson | ConvertFrom-Json -Depth 100
        }
        catch {
            Write-Warning "Failed to parse NVD CVE cache '$currentPath': $_"
            return @{}
        }

        $records = if ($document.PSObject.Properties['records']) { @($document.records) } else { @($document) }
        $nvdData = @{}
        foreach ($record in $records) {
            if ($null -eq $record) {
                continue
            }

            $cveId = [string]$record.PSObject.Properties['CveId']?.Value
            if ([string]::IsNullOrWhiteSpace($cveId)) {
                continue
            }

            $weaknesses = @(ConvertTo-NvdStringArray -Value $record.PSObject.Properties['Weaknesses']?.Value)
            $nvdData[$cveId] = @{
                PublishedDate = Convert-ToYmdDate -DateValue $record.PSObject.Properties['PublishedDate']?.Value
                LastModifiedDate = Convert-ToYmdDate -DateValue $record.PSObject.Properties['LastModifiedDate']?.Value
                VulnerabilityDescription = ConvertTo-NvdDescriptionValue -Value $record.PSObject.Properties['VulnerabilityDescription']?.Value
                BaseScore = $record.PSObject.Properties['BaseScore']?.Value
                BaseSeverity = [string]$record.PSObject.Properties['BaseSeverity']?.Value
                Vector = [string]$record.PSObject.Properties['Vector']?.Value
                CisaExploitAdd = Convert-ToYmdDate -DateValue $record.PSObject.Properties['CisaExploitAdd']?.Value
                CisaActionDue = Convert-ToYmdDate -DateValue $record.PSObject.Properties['CisaActionDue']?.Value
                CisaRequiredAction = [string]$record.PSObject.Properties['CisaRequiredAction']?.Value
                Weaknesses = if ($weaknesses.Count -gt 0) { @($weaknesses) } else { $null }
            }
        }

        Write-Information "  Loaded NVD enrichment data for $($nvdData.Count) CVE(s)" -InformationAction Continue
        return $nvdData
    }
}