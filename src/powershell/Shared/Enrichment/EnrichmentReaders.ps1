# Shared enrichment readers used by dashboard generation, validation, and Azure
# packaging outputs.

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

        $parts = @(ConvertTo-AdvancedHuntingStringArray -Value $Value)
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
                    $cveId = [string]$record.PSObject.Properties['CveId']?.Value
                    if (-not [string]::IsNullOrWhiteSpace($cveId) -and -not $ahData.ContainsKey($cveId)) {
                        $pdRaw = $record.PSObject.Properties['PublishedDate']?.Value
                        $rawDescription = $record.PSObject.Properties['VulnerabilityDescription']?.Value
                        $rawAffectedSoftware = $record.PSObject.Properties['AffectedSoftware']?.Value
                        $affectedSoftware = @(ConvertTo-AdvancedHuntingStringArray -Value $rawAffectedSoftware)
                        $ahData[$cveId] = @{
                            PublishedDate = Convert-ToYmdDate -DateValue $pdRaw
                            VulnerabilityDescription = ConvertTo-AdvancedHuntingDescriptionValue -Value $rawDescription
                            EpssScore = $record.PSObject.Properties['EpssScore']?.Value
                            AffectedSoftware = if ($affectedSoftware.Count -gt 0) { @($affectedSoftware) } else { $null }
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
                Write-Information '  No Advanced Hunting software inventory data files found.' -InformationAction Continue
                return @{}
            }

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

    function Add-AdvancedHuntingLoggedOnUserValue {
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
                    Add-AdvancedHuntingLoggedOnUserValue -Value $parsedValue -Values $Values -Seen $Seen
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
                Add-AdvancedHuntingLoggedOnUserValue -Value $property.Value -Values $Values -Seen $Seen
            }
            return
        }

        if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
            foreach ($item in $Value) {
                Add-AdvancedHuntingLoggedOnUserValue -Value $item -Values $Values -Seen $Seen
            }
            return
        }

        $fallbackText = [string]$Value
        if (-not [string]::IsNullOrWhiteSpace($fallbackText) -and $Seen.Add($fallbackText)) {
            $Values.Add($fallbackText)
        }
    }

    function ConvertTo-AdvancedHuntingLoggedOnUserList {
        [CmdletBinding()]
        [OutputType([string[]])]
        param(
            [Parameter(Mandatory = $false)]
            [AllowNull()]
            $Value
        )

        $values = [System.Collections.Generic.List[string]]::new()
        $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        Add-AdvancedHuntingLoggedOnUserValue -Value $Value -Values $values -Seen $seen
        return [string[]]$values.ToArray()
    }

    return Invoke-WithStoreLock -BasePath $Path -StoreName 'advancedhunting' -ScriptBlock {
        Restore-StoreTransaction -BasePath $Path -StoreName 'advancedhunting'

        Write-Information "Reading Advanced Hunting device-user data from $Path..." -InformationAction Continue

        $deviceUsers = @{}
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
                Write-Information '  No Advanced Hunting device-user data files found.' -InformationAction Continue
                return @{}
            }

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

                    $loggedOnUsers = @(ConvertTo-AdvancedHuntingLoggedOnUserList -Value $record.PSObject.Properties['LoggedOnUsers']?.Value)
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