# Shared enrichment and source-row projection helpers used by dashboard generation
# and validation.

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

function New-MachineInfoObject {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Machine
    )

    if ($null -eq $Machine) {
        return $null
    }

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

function Get-FilteredAffectedSoftware {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $AdvancedHuntingRecord,

        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.HashSet[string]]$VendorSet
    )

    if ($null -eq $AdvancedHuntingRecord) {
        return $null
    }

    $affectedSoftwareSource = @(Get-StringArray -Value $AdvancedHuntingRecord.AffectedSoftware)
    if (@($affectedSoftwareSource).Count -eq 0) {
        return $null
    }

    $filtered = [System.Collections.Generic.List[string]]::new()
    foreach ($software in $affectedSoftwareSource) {
        $vendor = if ($software -match ':') { $software.Split(':', 2)[0] } else { $software }
        $vendorMatchKey = Get-VendorMatchKey -Vendor $vendor
        if (-not [string]::IsNullOrWhiteSpace($vendorMatchKey) -and $VendorSet.Contains($vendorMatchKey)) {
            $filtered.Add([string]$software)
        }
    }

    if (@($filtered).Count -eq 0) {
        return $null
    }

    return @($filtered)
}

function Get-SourceCveEnrichment {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CveId,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $AdvancedHunting,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $NvdCveData,

        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.HashSet[string]]$VendorSet
    )

    $ahRecord = if ($null -ne $AdvancedHunting) { $AdvancedHunting[$CveId] } else { $null }
    $nvdRecord = if ($null -ne $NvdCveData) { $NvdCveData[$CveId] } else { $null }

    return [PSCustomObject]@{
        PublishedDate = if ($ahRecord -and $ahRecord.PublishedDate) { [string]$ahRecord.PublishedDate } elseif ($nvdRecord) { [string]$nvdRecord.PublishedDate } else { $null }
        VulnerabilityDescription = if ($ahRecord -and $ahRecord.VulnerabilityDescription) { [string]$ahRecord.VulnerabilityDescription } elseif ($nvdRecord) { [string]$nvdRecord.VulnerabilityDescription } else { $null }
        EpssScore = if ($ahRecord) { $ahRecord.EpssScore } else { $null }
        AffectedSoftware = Get-FilteredAffectedSoftware -AdvancedHuntingRecord $ahRecord -VendorSet $VendorSet
        IsExploitAvailable = if ($ahRecord -is [hashtable] -and $ahRecord.ContainsKey('IsExploitAvailable')) { $ahRecord.IsExploitAvailable } else { $null }
        NvdLastModifiedDate = if ($nvdRecord) { [string]$nvdRecord.LastModifiedDate } else { $null }
        NvdBaseScore = if ($nvdRecord) { $nvdRecord.BaseScore } else { $null }
        NvdBaseSeverity = if ($nvdRecord) { [string]$nvdRecord.BaseSeverity } else { $null }
        NvdVector = if ($nvdRecord) { [string]$nvdRecord.Vector } else { $null }
        NvdKevDate = if ($nvdRecord) { [string]$nvdRecord.CisaExploitAdd } else { $null }
        NvdActionDue = if ($nvdRecord) { [string]$nvdRecord.CisaActionDue } else { $null }
        NvdRequiredAction = if ($nvdRecord) { [string]$nvdRecord.CisaRequiredAction } else { $null }
        NvdWeaknesses = if ($nvdRecord -and $nvdRecord.Weaknesses) { @(Get-StringArray -Value $nvdRecord.Weaknesses) } else { $null }
    }
}

function Get-SourceInventoryEnrichment {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        $Record,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $AdvancedHuntingInventory
    )

    $emptyInventory = [PSCustomObject]@{
        ProductCodeCpe = $null
        EndOfSupportStatus = $null
        EndOfSupportDate = $null
    }
    if ($null -eq $AdvancedHuntingInventory) {
        return $emptyInventory
    }

    $inventoryKey = Get-AdvancedHuntingInventoryMatchKey `
        -DeviceId ([string](Get-VulnPropertyValue -InputObject $Record -Name 'DeviceId')) `
        -SoftwareVendor ([string](Get-VulnPropertyValue -InputObject $Record -Name 'SoftwareVendor')) `
        -SoftwareName ([string](Get-VulnPropertyValue -InputObject $Record -Name 'SoftwareName')) `
        -SoftwareVersion ([string](Get-VulnPropertyValue -InputObject $Record -Name 'SoftwareVersion'))
    if ([string]::IsNullOrWhiteSpace($inventoryKey)) {
        return $emptyInventory
    }

    $inventoryRecord = $AdvancedHuntingInventory[$inventoryKey]
    if ($null -eq $inventoryRecord) {
        return $emptyInventory
    }

    return [PSCustomObject]@{
        ProductCodeCpe = [string]$inventoryRecord.ProductCodeCpe
        EndOfSupportStatus = [string]$inventoryRecord.EndOfSupportStatus
        EndOfSupportDate = [string]$inventoryRecord.EndOfSupportDate
    }
}