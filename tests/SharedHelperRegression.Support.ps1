# Shared-helper regression fragment (Support). Dot-sourced by Run-SharedHelperRegression.ps1; not an entrypoint.

function Assert-True {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Condition,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Get-OutputRecordText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Record
    )

    if ($null -eq $Record) {
        return $null
    }

    if ($Record -is [System.Management.Automation.InformationRecord]) {
        return [string]$Record.MessageData
    }

    return ($Record | Out-String).Trim()
}

function Get-TestVulnRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id,

        [Parameter(Mandatory = $true)]
        [string]$CveId,

        [Parameter(Mandatory = $true)]
        [string]$SnapshotDate,

        [Parameter(Mandatory = $true)]
        [string]$Version
    )

    return [PSCustomObject]@{
        Id                           = $Id
        DeviceId                     = 'device-001'
        DeviceName                   = 'device01.contoso.com'
        RbacGroupName                = 'Servers'
        OSPlatform                   = 'Windows 11'
        OSVersion                    = '10.0.22631'
        MachineTags                  = @('Prod')
        CveId                        = $CveId
        SoftwareVendor               = 'Contoso'
        SoftwareName                 = 'Legacy Agent'
        SoftwareVersion              = $Version
        VulnerabilitySeverityLevel   = 'High'
        CvssScore                    = 8.1
        ExploitabilityLevel          = 'ExploitationLikely'
        RecommendationReference      = 'KB000001'
        RecommendedSecurityUpdate    = 'KB000001'
        RecommendedSecurityUpdateId  = 'KB000001'
        RecommendedSecurityUpdateUrl = 'https://example.invalid/kb000001'
        SecurityUpdateAvailable      = $true
        FirstSeenTimestamp           = $SnapshotDate
        LastSeenTimestamp            = $SnapshotDate
        DiskPaths                    = @('C:\Program Files\Legacy Agent\agent.exe')
        RegistryPaths                = @('HKLM\Software\Contoso\LegacyAgent')
        CveBatchTitle                = 'January 2026 Security Updates'
        CveBatchUrl                  = 'https://example.invalid/batch/jan-2026'
        IsOnboarded                  = $true
    }
}

function Get-TestMachineRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id
    )

    return [PSCustomObject]@{
        id                    = $Id
        computerDnsName       = ($Id + '.contoso.com')
        rbacGroupName         = 'Servers'
        osPlatform            = 'Windows'
        osVersion             = '10.0.22631'
        machineTags           = @('Prod')
        lastIpAddress         = '10.0.0.10'
        lastExternalIpAddress = '52.0.0.10'
        healthStatus          = 'Active'
        riskScore             = 'Medium'
        exposureLevel         = 'High'
        deviceValue           = 'Normal'
        managedBy             = 'Intune'
        isAadJoined           = $true
        lastSeen              = '2026-04-22T00:00:00Z'
        firstSeen             = '2026-04-01T00:00:00Z'
    }
}

function Get-TestQuarterlyHistoryDocument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PeriodKey,

        [Parameter(Mandatory = $true)]
        [object[]]$Snapshots
    )

    $latestDate = $null
    foreach ($snapshot in @($Snapshots)) {
        if ($null -eq $snapshot) { continue }
        $snapshotDate = [string](Get-VulnPropertyValue -InputObject $snapshot -Name 'date')
        if ([string]::IsNullOrWhiteSpace($snapshotDate)) { continue }

        if ([string]::IsNullOrWhiteSpace($latestDate) -or ([datetime]$snapshotDate -gt [datetime]$latestDate)) {
            $latestDate = $snapshotDate
        }
    }

    return [PSCustomObject]@{
        year = [int]$PeriodKey.Substring(0, 4)
        period = $PeriodKey
        quarter = [int]$PeriodKey.Substring($PeriodKey.Length - 1)
        latestDate = $latestDate
        snapshots = @($Snapshots)
    }
}

function Invoke-WithContentDictionaryStreamProbe {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$DeviceProfiles,

        [Parameter(Mandatory = $true)]
        [object[]]$ContentTemplates,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Action
    )

    $originalArrayEntriesReader = ${function:Read-VulnContentDictionaryArrayEntries}
    $originalAddNormalizedDevice = ${function:Add-NormalizedDevice}
    $originalResolveNormalizedContentLookup = ${function:Resolve-NormalizedContentLookup}
    $deviceProfileEntries = @($DeviceProfiles)
    $contentTemplateEntries = @($ContentTemplates)
    $deviceProfileReadCount = 0
    $contentTemplateReadCount = 0
    $probeState = [PSCustomObject]@{
        DeviceProfilesBuffered = $false
        ContentTemplatesBuffered = $false
        FirstDeviceProfileProcessed = $false
        FirstContentTemplateProcessed = $false
    }

    try {
        Set-Item -Path Function:Read-VulnContentDictionaryArrayEntries -Value ({
                param(
                    [Parameter(Mandatory = $true)]
                    [string]$Path,

                    [Parameter(Mandatory = $true)]
                    [ValidateSet('deviceProfiles', 'contentTemplates')]
                    [string]$PropertyName
                )

                $null = $Path

                $entries = switch ($PropertyName) {
                    'deviceProfiles' { $deviceProfileReadCount++; $deviceProfileEntries }
                    'contentTemplates' { $contentTemplateReadCount++; $contentTemplateEntries }
                    default { @() }
                }
                $isNormalizationRead = switch ($PropertyName) {
                    'deviceProfiles' { $deviceProfileReadCount -gt 1 }
                    'contentTemplates' { $contentTemplateReadCount -gt 1 }
                    default { $false }
                }

                if ($entries.Count -eq 0) {
                    return
                }

                Write-Output -InputObject $entries[0] -NoEnumerate
                for ($entryIndex = 1; $entryIndex -lt $entries.Count; $entryIndex++) {
                    switch ($PropertyName) {
                        'deviceProfiles' {
                            if ($isNormalizationRead -and -not $probeState.FirstDeviceProfileProcessed) {
                                $probeState.DeviceProfilesBuffered = $true
                            }
                        }
                        'contentTemplates' {
                            if ($isNormalizationRead -and -not $probeState.FirstContentTemplateProcessed) {
                                $probeState.ContentTemplatesBuffered = $true
                            }
                        }
                    }

                    Write-Output -InputObject $entries[$entryIndex] -NoEnumerate
                }
            }.GetNewClosure())

        Set-Item -Path Function:Add-NormalizedDevice -Value ({
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

                    [Parameter(Mandatory = $true)]
                    [pscustomobject]$Context
                )

                if (-not $probeState.FirstDeviceProfileProcessed) {
                    $probeState.FirstDeviceProfileProcessed = $true
                }

                & $originalAddNormalizedDevice @PSBoundParameters
            }.GetNewClosure())

        Set-Item -Path Function:Resolve-NormalizedContentLookup -Value ({
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

                if (-not $probeState.FirstContentTemplateProcessed) {
                    $probeState.FirstContentTemplateProcessed = $true
                }

                & $originalResolveNormalizedContentLookup @PSBoundParameters
            }.GetNewClosure())

        $result = & $Action
        return [PSCustomObject]@{
            Result = $result
            State = $probeState
        }
    }
    finally {
        if ($null -ne $originalArrayEntriesReader) {
            Set-Item -Path Function:Read-VulnContentDictionaryArrayEntries -Value $originalArrayEntriesReader
        }

        if ($null -ne $originalAddNormalizedDevice) {
            Set-Item -Path Function:Add-NormalizedDevice -Value $originalAddNormalizedDevice
        }

        if ($null -ne $originalResolveNormalizedContentLookup) {
            Set-Item -Path Function:Resolve-NormalizedContentLookup -Value $originalResolveNormalizedContentLookup
        }
    }
}

function Initialize-RegressionDashboardLibraryCache {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$BasePath)

    $libraryCachePath = Join-Path $BasePath '.dashboard-cache\libraries'
    [void](New-Item -Path $libraryCachePath -ItemType Directory -Force)
    foreach ($library in @(
            @{ Name = 'Chart.js'; Url = 'https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.js' },
            @{ Name = 'pdfmake'; Url = 'https://cdnjs.cloudflare.com/ajax/libs/pdfmake/0.2.7/pdfmake.min.js' },
            @{ Name = 'vfs_fonts'; Url = 'https://cdnjs.cloudflare.com/ajax/libs/pdfmake/0.2.7/vfs_fonts.min.js' },
            @{ Name = 'html2canvas'; Url = 'https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js' },
            @{ Name = 'pako'; Url = 'https://cdn.jsdelivr.net/npm/pako@2.1.0/dist/pako.min.js' }
        )) {
        $hashBytes = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes([string]$library.Url))
        $urlHash = ([System.BitConverter]::ToString($hashBytes)).Replace('-', '').ToLowerInvariant().Substring(0, 16)
        $safeName = ([string]$library.Name -replace '[^A-Za-z0-9._-]', '-')
        $cachePath = Join-Path $libraryCachePath ("{0}-{1}.js" -f $safeName, $urlHash)
        [System.IO.File]::WriteAllText($cachePath, ('/* offline regression fixture: ' + $safeName + ' */'), [System.Text.UTF8Encoding]::new($false))
    }
}
