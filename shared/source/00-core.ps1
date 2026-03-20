Set-StrictMode -Version Latest

# Canonical shared helper surface for the Defender reporting scripts.
#
# This file is the authoritative source for reusable logic shared by:
# - Invoke-VulnerabilityExport.ps1
# - Generate-VulnerabilityDashboard.ps1
# - the generated Azure Automation runbook
#
# TEMPORARY THROUGH 2026-07-01:
# The vulnerability current/history migration and legacy compatibility paths
# remain here in a dedicated section so they can be removed cleanly once all
# callers have upgraded off the legacy VulnExport_<group>_<date>.json(.gz)
# snapshot layout.

$Script:VulnCurrentFileName = 'VulnExport_current.json.gz'
$Script:VulnHistoryFileNamePattern = 'VulnHistory_{0}.json.gz'
$Script:VulnHistoryRowsFileNamePattern = 'VulnHistoryRows_{0}.json.gz'
$Script:MachineCurrentFileName = 'Machines_Current.json.gz'
$Script:MachineHistoryFileName = 'Machines_History.json.gz'
$Script:MachineHistoryQuarterlyFileNamePattern = 'Machines_History_{0}.json.gz'
$Script:AdvancedHuntingCurrentFileName = 'AdvancedHunting_Current.json.gz'
$Script:LegacyVulnMigrationRemovalDate = '2026-07-01'
$Script:VulnDiskPartitionCount = 64

function Get-StoreLockName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $true)]
        [string]$StoreName
    )

    $storeKey = ([System.IO.Path]::GetFullPath($BasePath) + '|' + $StoreName).ToLowerInvariant()
    $hashBytes = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($storeKey))
    $hash = ([System.BitConverter]::ToString($hashBytes)).Replace('-', '').ToLowerInvariant()
    return "Global\DefenderReporting.$hash"
}

function Invoke-WithStoreLock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $true)]
        [string]$StoreName,

        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds = 300
    )

    $mutexName = Get-StoreLockName -BasePath $BasePath -StoreName $StoreName
    $mutex = [System.Threading.Mutex]::new($false, $mutexName)
    $acquired = $false

    try {
        $acquired = $mutex.WaitOne([TimeSpan]::FromSeconds($TimeoutSeconds))
        if (-not $acquired) {
            throw "Timed out waiting for the '$StoreName' store lock in '$BasePath'."
        }

        return & $ScriptBlock
    }
    finally {
        if ($acquired) {
            [void]$mutex.ReleaseMutex()
        }
        $mutex.Dispose()
    }
}

function Invoke-FullGarbageCollection {
    [CmdletBinding()]
    param()

    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
    [System.GC]::Collect()
}

function Get-StoreTransactionJournalPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $true)]
        [string]$StoreName
    )

    return Join-Path -Path $BasePath -ChildPath (".{0}.transaction.json" -f $StoreName)
}

function Write-StoreTransactionState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $State,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $State | ConvertTo-Json -Depth 20 | Set-Content -Path $Path -Encoding utf8
}

function Read-StoreTransactionState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }

    return (Get-Content -Path $Path -Raw | ConvertFrom-Json -Depth 20)
}

function Remove-StoreTransactionArtifacts {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$JournalPath,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$TransactionRoot
    )

    if (-not [string]::IsNullOrWhiteSpace($TransactionRoot) -and (Test-Path -LiteralPath $TransactionRoot)) {
        Remove-Item -LiteralPath $TransactionRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    if (Test-Path -LiteralPath $JournalPath) {
        Remove-Item -LiteralPath $JournalPath -Force -ErrorAction SilentlyContinue
    }
}

function Restore-StoreTransaction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $true)]
        [string]$StoreName
    )

    $journalPath = Get-StoreTransactionJournalPath -BasePath $BasePath -StoreName $StoreName
    $state = Read-StoreTransactionState -Path $journalPath
    if ($null -eq $state) {
        return
    }

    $phase = [string]$state.Phase
    if ($phase -eq 'Committed') {
        Remove-StoreTransactionArtifacts -JournalPath $journalPath -TransactionRoot ([string]$state.TransactionRoot)
        return
    }

    foreach ($file in @($state.Files)) {
        $targetPath = [string]$file.TargetPath
        $stagePath = [string]$file.StagePath
        $backupPath = [string]$file.BackupPath
        $targetExisted = ($file.TargetExisted -eq $true)

        if ($targetExisted -and (Test-Path -LiteralPath $backupPath -PathType Leaf)) {
            if (Test-Path -LiteralPath $targetPath -PathType Leaf) {
                Remove-Item -LiteralPath $targetPath -Force -ErrorAction SilentlyContinue
            }
            Move-Item -LiteralPath $backupPath -Destination $targetPath -Force
        }
        elseif ((-not $targetExisted) -and (Test-Path -LiteralPath $targetPath -PathType Leaf)) {
            Remove-Item -LiteralPath $targetPath -Force -ErrorAction SilentlyContinue
        }

        if (Test-Path -LiteralPath $stagePath -PathType Leaf) {
            Remove-Item -LiteralPath $stagePath -Force -ErrorAction SilentlyContinue
        }
    }

    foreach ($removed in @($state.RemovedFiles)) {
        $targetPath = [string]$removed.TargetPath
        $backupPath = [string]$removed.BackupPath

        if (Test-Path -LiteralPath $backupPath -PathType Leaf) {
            if (Test-Path -LiteralPath $targetPath -PathType Leaf) {
                Remove-Item -LiteralPath $targetPath -Force -ErrorAction SilentlyContinue
            }
            Move-Item -LiteralPath $backupPath -Destination $targetPath -Force
        }
    }

    Remove-StoreTransactionArtifacts -JournalPath $journalPath -TransactionRoot ([string]$state.TransactionRoot)
}

function Publish-StoreFilesTransactional {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $true)]
        [string]$StoreName,

        [Parameter(Mandatory = $true)]
        [object[]]$Files,

        [Parameter(Mandatory = $false)]
        [string[]]$RemovePaths
    )

    Restore-StoreTransaction -BasePath $BasePath -StoreName $StoreName

    $transactionRoot = Join-Path $BasePath ('.' + $StoreName + '-transaction-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $transactionRoot -ItemType Directory -Force)

    $journalPath = Get-StoreTransactionJournalPath -BasePath $BasePath -StoreName $StoreName
    $targetPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $fileEntries = [System.Collections.Generic.List[object]]::new()
    $removedEntries = [System.Collections.Generic.List[object]]::new()
    $index = 0

    foreach ($file in @($Files)) {
        $targetPath = [string]$file.TargetPath
        [void]$targetPaths.Add($targetPath)

        $fileEntries.Add([PSCustomObject]@{
            TargetPath = $targetPath
            StagePath = [string]$file.StagePath
            BackupPath = Join-Path $transactionRoot ('replace-' + $index + '-' + [System.IO.Path]::GetFileName($targetPath) + '.bak')
            TargetExisted = (Test-Path -LiteralPath $targetPath -PathType Leaf)
        })
        $index++
    }

    $removeIndex = 0
    foreach ($removePath in @($RemovePaths)) {
        if ([string]::IsNullOrWhiteSpace($removePath)) { continue }
        if ($targetPaths.Contains($removePath)) { continue }
        if (-not (Test-Path -LiteralPath $removePath -PathType Leaf)) { continue }

        $removedEntries.Add([PSCustomObject]@{
            TargetPath = $removePath
            BackupPath = Join-Path $transactionRoot ('remove-' + $removeIndex + '-' + [System.IO.Path]::GetFileName($removePath) + '.bak')
        })
        $removeIndex++
    }

    $state = [PSCustomObject]@{
        StoreName = $StoreName
        TransactionRoot = $transactionRoot
        Phase = 'Prepared'
        Files = @($fileEntries)
        RemovedFiles = @($removedEntries)
    }
    Write-StoreTransactionState -State $state -Path $journalPath

    try {
        foreach ($entry in @($fileEntries)) {
            if ($entry.TargetExisted) {
                [System.IO.File]::Replace($entry.StagePath, $entry.TargetPath, $entry.BackupPath, $true)
            }
            else {
                Move-Item -LiteralPath $entry.StagePath -Destination $entry.TargetPath -Force
            }
        }

        foreach ($entry in @($removedEntries)) {
            Move-Item -LiteralPath $entry.TargetPath -Destination $entry.BackupPath -Force
        }

        $state.Phase = 'Committed'
        Write-StoreTransactionState -State $state -Path $journalPath
        Remove-StoreTransactionArtifacts -JournalPath $journalPath -TransactionRoot $transactionRoot
    }
    catch {
        Restore-StoreTransaction -BasePath $BasePath -StoreName $StoreName
        throw
    }
}

function Get-VulnPropertyValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($null -eq $InputObject) { return $null }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Get-VulnCurrentPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    return Join-Path -Path $BasePath -ChildPath $Script:VulnCurrentFileName
}

function Test-VulnStoreExistence {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    if (Test-Path -Path (Get-VulnCurrentPath -BasePath $BasePath)) {
        return $true
    }

    $historyFiles = @(Get-ChildItem -Path $BasePath -Filter 'VulnHistory_*.json.gz' -File -ErrorAction SilentlyContinue)
    return $historyFiles.Count -gt 0
}

function New-QuarterPeriodKey {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [int]$Year,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 4)]
        [int]$Quarter
    )

    return ('{0:D4}Q{1}' -f $Year, $Quarter)
}

function Get-QuarterNumberFromDate {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Date
    )

    $month = ([datetime]$Date).Month
    return [int][math]::Ceiling($month / 3)
}

function Get-QuarterPeriodKeyFromDate {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Date
    )

    $dt = [datetime]$Date
    return (New-QuarterPeriodKey -Year $dt.Year -Quarter (Get-QuarterNumberFromDate -Date $Date))
}

function Get-QuarterPeriodInfo {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PeriodKey
    )

    $match = [regex]::Match($PeriodKey, '^(?<year>\d{4})Q(?<quarter>[1-4])$')
    if (-not $match.Success) {
        throw "Invalid vulnerability history period key '$PeriodKey'."
    }

    return [PSCustomObject]@{
        PeriodKey = $PeriodKey
        Year = [int]$match.Groups['year'].Value
        Quarter = [int]$match.Groups['quarter'].Value
    }
}

function New-VulnHistoryPeriodKey {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [int]$Year,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 4)]
        [int]$Quarter
    )

    return (New-QuarterPeriodKey -Year $Year -Quarter $Quarter)
}

function Get-VulnHistoryQuarterFromDate {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Date
    )

    return (Get-QuarterNumberFromDate -Date $Date)
}

function Get-VulnHistoryPeriodKeyFromDate {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Date
    )

    return (Get-QuarterPeriodKeyFromDate -Date $Date)
}

function Get-VulnHistoryPeriodInfo {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PeriodKey
    )

    return (Get-QuarterPeriodInfo -PeriodKey $PeriodKey)
}

function Get-VulnHistoryPeriodKeyFromDocument {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        $HistoryDocument
    )

    $period = [string](Get-VulnPropertyValue -InputObject $HistoryDocument -Name 'period')
    if (-not [string]::IsNullOrWhiteSpace($period)) {
        return $period
    }

    $yearValue = Get-VulnPropertyValue -InputObject $HistoryDocument -Name 'year'
    $quarterValue = Get-VulnPropertyValue -InputObject $HistoryDocument -Name 'quarter'
    if ($null -ne $yearValue -and $null -ne $quarterValue) {
        return (New-VulnHistoryPeriodKey -Year ([int]$yearValue) -Quarter ([int]$quarterValue))
    }

    return $null
}

function Convert-VulnHistoryDocumentToQuarterlyDocuments {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $true)]
        $HistoryDocument
    )

    $existingPeriodKey = Get-VulnHistoryPeriodKeyFromDocument -HistoryDocument $HistoryDocument
    if (-not [string]::IsNullOrWhiteSpace($existingPeriodKey)) {
        $periodInfo = Get-VulnHistoryPeriodInfo -PeriodKey $existingPeriodKey
        $latestDate = Get-VulnHistoryDocumentLatestDate -HistoryDocument $HistoryDocument
        return @([PSCustomObject]@{
            year = $periodInfo.Year
            quarter = $periodInfo.Quarter
            period = $periodInfo.PeriodKey
            latestDate = $latestDate
            snapshots = @($HistoryDocument.snapshots)
        })
    }

    $documentsByPeriod = @{}
    $latestByPeriod = @{}
    foreach ($snapshot in @($HistoryDocument.snapshots)) {
        if ($null -eq $snapshot) { continue }
        $snapshotDate = Convert-VulnToYmdDate -DateValue (Get-VulnPropertyValue -InputObject $snapshot -Name 'date')
        if ([string]::IsNullOrWhiteSpace($snapshotDate)) { continue }

        $periodKey = Get-VulnHistoryPeriodKeyFromDate -Date $snapshotDate
        if (-not $documentsByPeriod.ContainsKey($periodKey)) {
            $periodInfo = Get-VulnHistoryPeriodInfo -PeriodKey $periodKey
            $documentsByPeriod[$periodKey] = [PSCustomObject]@{
                year = $periodInfo.Year
                quarter = $periodInfo.Quarter
                period = $periodInfo.PeriodKey
                latestDate = ''
                snapshots = @()
            }
        }

        $documentsByPeriod[$periodKey].snapshots += $snapshot
        $latestByPeriod[$periodKey] = Get-MaxVulnDate -Primary ([string]$latestByPeriod[$periodKey]) -Secondary $snapshotDate
    }

    foreach ($periodKey in @($documentsByPeriod.Keys)) {
        $documentsByPeriod[$periodKey].latestDate = [string]$latestByPeriod[$periodKey]
    }

    return @($documentsByPeriod.Values | Sort-Object period)
}

function Get-VulnHistoryPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$PeriodKey,

        [Parameter(Mandatory = $false)]
        [int]$Year
    )

    if ([string]::IsNullOrWhiteSpace($PeriodKey)) {
        $PeriodKey = [string]$Year
    }

    return Join-Path -Path $BasePath -ChildPath ([string]::Format($Script:VulnHistoryFileNamePattern, $PeriodKey))
}

function Get-VulnHistoryRowsPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$PeriodKey,

        [Parameter(Mandatory = $false)]
        [int]$Year
    )

    if ([string]::IsNullOrWhiteSpace($PeriodKey)) {
        $PeriodKey = [string]$Year
    }

    return Join-Path -Path $BasePath -ChildPath ([string]::Format($Script:VulnHistoryRowsFileNamePattern, $PeriodKey))
}

function Test-IsVulnHistoryFileName {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    return ($Name -match '^VulnHistory_(?:\d{4}Q[1-4]|\d{4})\.json\.gz$')
}

function Test-IsVulnHistoryRowsFileName {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    return ($Name -match '^VulnHistoryRows_(?:\d{4}Q[1-4]|\d{4})\.json\.gz$')
}

function Get-VulnHistoryPublishedNameSet {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.HashSet[string]])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$PeriodKeys
    )

    $publishedNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($periodKey in @($PeriodKeys | Sort-Object -Unique)) {
        if ([string]::IsNullOrWhiteSpace($periodKey)) { continue }
        [void]$publishedNames.Add([string]::Format($Script:VulnHistoryFileNamePattern, $periodKey))
        [void]$publishedNames.Add([string]::Format($Script:VulnHistoryRowsFileNamePattern, $periodKey))
    }

    return $publishedNames
}

function Get-VulnHistoryRemovePaths {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.Collections.Generic.HashSet[string]]$PublishedHistoryNames
    )

    if ($null -eq $PublishedHistoryNames) {
        $PublishedHistoryNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    }

    $removePaths = [System.Collections.Generic.List[string]]::new()
    foreach ($path in @(
        Get-ChildItem -Path $BasePath -Filter 'VulnHistory_*.json.gz' -File -ErrorAction SilentlyContinue |
            Where-Object { -not $PublishedHistoryNames.Contains($_.Name) } |
            ForEach-Object { $_.FullName }
    )) {
        $removePaths.Add($path)
    }

    foreach ($path in @(
        Get-ChildItem -Path $BasePath -Filter 'VulnHistoryRows_*.json.gz' -File -ErrorAction SilentlyContinue |
            Where-Object { -not $PublishedHistoryNames.Contains($_.Name) } |
            ForEach-Object { $_.FullName }
    )) {
        $removePaths.Add($path)
    }

    return [string[]]@($removePaths)
}

function Test-IsCanonicalExportStoreFileName {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($Name -in @(
        $Script:VulnCurrentFileName,
        $Script:MachineCurrentFileName,
        $Script:AdvancedHuntingCurrentFileName
    )) {
        return $true
    }

    if ((Test-IsVulnHistoryFileName -Name $Name) -or (Test-IsVulnHistoryRowsFileName -Name $Name)) {
        return $true
    }

    if (Test-IsMachineHistoryQuarterlyFileName -Name $Name) {
        return $true
    }

    return $false
}

function Test-IsNativeCompressedStoreFileName {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if (Test-IsCanonicalExportStoreFileName -Name $Name) {
        return $true
    }

    if ((Test-IsMachineHistorySegmentFileName -Name $Name) -or ($Name -eq $Script:MachineHistoryFileName)) {
        return $true
    }

    return $false
}

function Get-CanonicalExportStoreFileNames {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    return [string[]]@(
        Get-ChildItem -Path $BasePath -File -ErrorAction SilentlyContinue |
            Where-Object { Test-IsCanonicalExportStoreFileName -Name $_.Name } |
            Sort-Object Name |
            ForEach-Object { $_.Name }
    )
}

function Get-StaleExportStoreArtifactNames {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ExistingNames,

        [Parameter(Mandatory = $true)]
        [string[]]$CanonicalNames
    )

    $canonicalNameSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($name in @($CanonicalNames)) {
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        [void]$canonicalNameSet.Add($name)
    }

    $staleNames = [System.Collections.Generic.List[string]]::new()
    foreach ($name in @($ExistingNames | Sort-Object -Unique)) {
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        if ($canonicalNameSet.Contains($name)) { continue }

        if (
            (Test-IsVulnHistoryFileName -Name $name) -or
            (Test-IsVulnHistoryRowsFileName -Name $name) -or
            (Test-IsMachineHistoryQuarterlyFileName -Name $name) -or
            (Test-IsMachineHistorySegmentFileName -Name $name) -or
            ($name -eq $Script:MachineHistoryFileName)
        ) {
            $staleNames.Add($name)
        }
    }

    return [string[]]@($staleNames)
}

function Test-IsLegacyVulnSnapshotFileName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    return ($Name -match '^VulnExport_\d+_\d{4}-\d{2}-\d{2}\.json(?:\.gz)?$')
}

function Get-VulnSnapshotDateFromName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $match = [regex]::Match($Name, '\d{4}-\d{2}-\d{2}')
    if (-not $match.Success) {
        throw "Unable to parse snapshot date from '$Name'."
    }

    return $match.Value
}

function Get-VulnLegacySnapshotFile {
    [CmdletBinding()]
    [OutputType([System.IO.FileInfo[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $false)]
        [string[]]$LegacyFilePaths
    )

    if ($null -ne $LegacyFilePaths -and $LegacyFilePaths.Count -gt 0) {
        return [System.IO.FileInfo[]]@(
            $LegacyFilePaths |
                ForEach-Object {
                    if (Test-Path -LiteralPath $_ -PathType Leaf) {
                        Get-Item -LiteralPath $_
                    }
                } |
                Where-Object { $null -ne $_ -and (Test-IsLegacyVulnSnapshotFileName -Name $_.Name) } |
                Sort-Object Name
        )
    }

    return [System.IO.FileInfo[]]@(
        Get-ChildItem -Path $BasePath -Filter 'VulnExport_*' -File -ErrorAction SilentlyContinue |
            Where-Object { Test-IsLegacyVulnSnapshotFileName -Name $_.Name } |
            Sort-Object Name
    )
}

function Convert-VulnToYmdDate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$DateValue
    )

    return (Convert-ToYmdDate -DateValue $DateValue)
}

function Get-VulnNextDay {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Date
    )

    return ([datetime]$Date).AddDays(1).ToString('yyyy-MM-dd')
}

function Get-VulnPreviousDay {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Date
    )

    return ([datetime]$Date).AddDays(-1).ToString('yyyy-MM-dd')
}

function Get-MaxVulnDate {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Primary,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Secondary
    )

    if ([string]::IsNullOrWhiteSpace($Primary)) { return $Secondary }
    if ([string]::IsNullOrWhiteSpace($Secondary)) { return $Primary }
    if ([datetime]$Primary -ge [datetime]$Secondary) { return $Primary }
    return $Secondary
}

function Get-MinVulnDate {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Primary,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Secondary
    )

    if ([string]::IsNullOrWhiteSpace($Primary)) { return $Secondary }
    if ([string]::IsNullOrWhiteSpace($Secondary)) { return $Primary }
    if ([datetime]$Primary -le [datetime]$Secondary) { return $Primary }
    return $Secondary
}

function Get-NormalizedVulnSeenWindow {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$FirstSeenValue,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$LastSeenValue
    )

    $firstSeen = Convert-VulnToYmdDate -DateValue $FirstSeenValue
    $lastSeen = Convert-VulnToYmdDate -DateValue $LastSeenValue
    $wasReordered = $false

    if ($firstSeen -and $lastSeen -and [datetime]$firstSeen -gt [datetime]$lastSeen) {
        $temp = $firstSeen
        $firstSeen = $lastSeen
        $lastSeen = $temp
        $wasReordered = $true
    }

    return [PSCustomObject]@{
        FirstSeenTimestamp = $firstSeen
        LastSeenTimestamp = $lastSeen
        WasReordered = $wasReordered
    }
}

function Get-VulnCanonicalRowSignature {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Row
    )

    # Use only the stable vulnerability identity for versioning. Volatile enrichment
    # fields such as OS version, recommendations, and paths can change between
    # snapshots without indicating that the vulnerability itself disappeared.
    $id = [string](Get-VulnPropertyValue -InputObject $Row -Name 'Id')
    if (-not [string]::IsNullOrWhiteSpace($id)) {
        return $id
    }

    $payload = [ordered]@{
        DeviceId = [string](Get-VulnPropertyValue -InputObject $Row -Name 'DeviceId')
        CveId = [string](Get-VulnPropertyValue -InputObject $Row -Name 'CveId')
        SoftwareVendor = [string](Get-VulnPropertyValue -InputObject $Row -Name 'SoftwareVendor')
        SoftwareName = [string](Get-VulnPropertyValue -InputObject $Row -Name 'SoftwareName')
        SoftwareVersion = [string](Get-VulnPropertyValue -InputObject $Row -Name 'SoftwareVersion')
    }

    return ($payload | ConvertTo-Json -Compress -Depth 20)
}

function Copy-VulnRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Record
    )

    $copy = [ordered]@{}
    foreach ($prop in $Record.PSObject.Properties) {
        $copy[$prop.Name] = $prop.Value
    }
    return [PSCustomObject]$copy
}

function New-ClosedVulnEntry {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Record,

        [Parameter(Mandatory = $true)]
        [ValidateSet('removed', 'changed')]
        [string]$Reason,

        [Parameter(Mandatory = $true)]
        [string]$ClosedOn,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$ReplacementId
    )

    $row = Copy-VulnRecord -Record $Record
    $seenWindow = Get-NormalizedVulnSeenWindow `
        -FirstSeenValue (Get-VulnPropertyValue -InputObject $row -Name 'FirstSeenTimestamp') `
        -LastSeenValue (Get-VulnPropertyValue -InputObject $row -Name 'LastSeenTimestamp')
    $boundedLastSeen = if ($seenWindow.LastSeenTimestamp) { Get-MinVulnDate -Primary $seenWindow.LastSeenTimestamp -Secondary $ClosedOn } else { $ClosedOn }
    $boundedFirstSeen = if ($seenWindow.FirstSeenTimestamp) { Get-MinVulnDate -Primary $seenWindow.FirstSeenTimestamp -Secondary $boundedLastSeen } else { $boundedLastSeen }
    $row.FirstSeenTimestamp = $boundedFirstSeen
    $row.LastSeenTimestamp = $boundedLastSeen

    $entry = [ordered]@{
        reason = $Reason
        row = $row
    }

    if (-not [string]::IsNullOrWhiteSpace($ReplacementId)) {
        $entry.replacementId = $ReplacementId
    }

    return [PSCustomObject]$entry
}

function New-OpenVulnRecord {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Record,

        [Parameter(Mandatory = $true)]
        [string]$VersionStartDate
    )

    $open = Copy-VulnRecord -Record $Record
    $seenWindow = Get-NormalizedVulnSeenWindow `
        -FirstSeenValue (Get-VulnPropertyValue -InputObject $open -Name 'FirstSeenTimestamp') `
        -LastSeenValue (Get-VulnPropertyValue -InputObject $open -Name 'LastSeenTimestamp')
    $open.FirstSeenTimestamp = if ($seenWindow.FirstSeenTimestamp) { Get-MaxVulnDate -Primary $seenWindow.FirstSeenTimestamp -Secondary $VersionStartDate } else { $VersionStartDate }
    $open.LastSeenTimestamp = if ($seenWindow.LastSeenTimestamp) { Get-MaxVulnDate -Primary $seenWindow.LastSeenTimestamp -Secondary $open.FirstSeenTimestamp } else { $open.FirstSeenTimestamp }
    return $open
}

function Get-VulnHistorySeed {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PeriodKey
    )

    $periodInfo = Get-VulnHistoryPeriodInfo -PeriodKey $PeriodKey
    return [ordered]@{
        year = $periodInfo.Year
        quarter = $periodInfo.Quarter
        period = $periodInfo.PeriodKey
        latestDate = ''
        snapshots = @()
    }
}

function Get-VulnHistorySnapshotMap {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        $HistoryDocument
    )

    $map = @{}
    foreach ($snapshot in @($HistoryDocument.snapshots)) {
        if ($null -eq $snapshot) { continue }
        $map[[string]$snapshot.date] = $snapshot
    }
    return $map
}

function Read-GzipTextFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $fileStream = [System.IO.File]::OpenRead($Path)
    try {
        $header = New-Object byte[] 2
        $bytesRead = $fileStream.Read($header, 0, $header.Length)
        $fileStream.Position = 0

        if (($bytesRead -ne 2) -or $header[0] -ne 0x1f -or $header[1] -ne 0x8b) {
            $plainReader = [System.IO.StreamReader]::new($fileStream, [System.Text.UTF8Encoding]::new($false), $true)
            try {
                return $plainReader.ReadToEnd()
            }
            finally {
                $plainReader.Dispose()
            }
        }

        $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Decompress)
        try {
            $reader = [System.IO.StreamReader]::new($gzipStream, [System.Text.UTF8Encoding]::new($false))
            try {
                return $reader.ReadToEnd()
            }
            finally {
                $reader.Dispose()
            }
        }
        finally {
            $gzipStream.Dispose()
        }
    }
    finally {
        $fileStream.Dispose()
    }
}

function Read-GzipTextFilePrefix {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [int]$MaxChars = 4096
    )

    $fileStream = [System.IO.File]::OpenRead($Path)
    try {
        $header = New-Object byte[] 2
        $bytesRead = $fileStream.Read($header, 0, $header.Length)
        $fileStream.Position = 0

        $contentStream = if (($bytesRead -eq 2) -and $header[0] -eq 0x1f -and $header[1] -eq 0x8b) {
            [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Decompress)
        }
        else {
            $fileStream
        }

        try {
            $reader = [System.IO.StreamReader]::new($contentStream, [System.Text.UTF8Encoding]::new($false))
            try {
                $buffer = New-Object char[] $MaxChars
                $charsRead = $reader.Read($buffer, 0, $buffer.Length)
                if ($charsRead -le 0) {
                    return ''
                }

                return [string]::new($buffer, 0, $charsRead)
            }
            finally {
                $reader.Dispose()
            }
        }
        finally {
            if ($contentStream -ne $fileStream) {
                $contentStream.Dispose()
            }
        }
    }
    finally {
        $fileStream.Dispose()
    }
}

function Write-GzipTextFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Content
    )

    $fileStream = [System.IO.File]::Create($Path)
    try {
        $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Compress)
        try {
            $writer = [System.IO.StreamWriter]::new($gzipStream, [System.Text.UTF8Encoding]::new($false))
            try {
                $writer.Write($Content)
            }
            finally {
                $writer.Dispose()
            }
        }
        finally {
            $gzipStream.Dispose()
        }
    }
    finally {
        $fileStream.Dispose()
    }
}

function Read-VulnNdjsonLinesFromPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $fileStream = [System.IO.File]::OpenRead($Path)
    try {
        $contentStream = if ($Path.EndsWith('.gz', [System.StringComparison]::OrdinalIgnoreCase)) {
            [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Decompress)
        }
        else {
            $fileStream
        }

        try {
            $reader = [System.IO.StreamReader]::new($contentStream, [System.Text.UTF8Encoding]::new($false))
            try {
                while (-not $reader.EndOfStream) {
                    $line = $reader.ReadLine()
                    if ([string]::IsNullOrWhiteSpace($line)) { continue }
                    Write-Output $line
                }
            }
            finally {
                $reader.Dispose()
            }
        }
        finally {
            if ($contentStream -ne $fileStream) {
                $contentStream.Dispose()
            }
        }
    }
    finally {
        $fileStream.Dispose()
    }
}

function Read-VulnNdjsonRecordsFromPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    foreach ($line in Read-VulnNdjsonLinesFromPath -Path $Path) {
        $record = $line | ConvertFrom-Json -Depth 20
        if ($null -ne $record) {
            Write-Output $record
        }
    }
}

function Write-VulnCurrentFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [System.Collections.IEnumerable]$Records
    )

    $fileStream = [System.IO.File]::Create($Path)
    try {
        $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Compress)
        try {
            $writer = [System.IO.StreamWriter]::new($gzipStream, [System.Text.UTF8Encoding]::new($false))
            try {
                foreach ($record in $Records) {
                    if ($null -eq $record) { continue }
                    $writer.WriteLine(($record | ConvertTo-Json -Compress -Depth 20))
                }
            }
            finally {
                $writer.Dispose()
            }
        }
        finally {
            $gzipStream.Dispose()
        }
    }
    finally {
        $fileStream.Dispose()
    }
}

function Write-VulnCurrentFileFromNdjson {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [System.Collections.IEnumerable]$JsonLines
    )

    $fileStream = [System.IO.File]::Create($Path)
    try {
        $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Compress)
        try {
            $writer = [System.IO.StreamWriter]::new($gzipStream, [System.Text.UTF8Encoding]::new($false))
            try {
                foreach ($jsonLine in $JsonLines) {
                    if ([string]::IsNullOrWhiteSpace([string]$jsonLine)) { continue }
                    $writer.WriteLine([string]$jsonLine)
                }
            }
            finally {
                $writer.Dispose()
            }
        }
        finally {
            $gzipStream.Dispose()
        }
    }
    finally {
        $fileStream.Dispose()
    }
}

function Read-VulnHistoryDocument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $content = Read-GzipTextFile -Path $Path
    if ([string]::IsNullOrWhiteSpace($content)) {
        throw "History file '$Path' is empty."
    }

    return ($content | ConvertFrom-Json -Depth 100)
}

function Read-VulnHistoryRowsFromPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $fileStream = [System.IO.File]::OpenRead($Path)
    try {
        $header = New-Object byte[] 2
        $bytesRead = $fileStream.Read($header, 0, $header.Length)
        $fileStream.Position = 0

        $contentStream = if (($bytesRead -eq 2) -and $header[0] -eq 0x1f -and $header[1] -eq 0x8b) {
            [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Decompress)
        }
        else {
            $fileStream
        }

        try {
            $reader = [System.IO.StreamReader]::new($contentStream, [System.Text.UTF8Encoding]::new($false))
            try {
                $jsonReader = [Newtonsoft.Json.JsonTextReader]::new($reader)
                try {
                    while ($jsonReader.Read()) {
                        if ($jsonReader.TokenType -ne [Newtonsoft.Json.JsonToken]::PropertyName) { continue }
                        if ([string]$jsonReader.Value -ne 'row') { continue }
                        if (-not $jsonReader.Read()) { break }
                        if ($jsonReader.TokenType -eq [Newtonsoft.Json.JsonToken]::Null) { continue }

                        $rowToken = [Newtonsoft.Json.Linq.JToken]::ReadFrom($jsonReader)
                        if ($null -eq $rowToken) { continue }

                        $row = $rowToken.ToString([Newtonsoft.Json.Formatting]::None) | ConvertFrom-Json -Depth 20
                        if ($null -ne $row) {
                            Write-Output $row
                        }
                    }
                }
                finally {
                    $jsonReader.Close()
                }
            }
            finally {
                $reader.Dispose()
            }
        }
        finally {
            if ($contentStream -ne $fileStream) {
                $contentStream.Dispose()
            }
        }
    }
    finally {
        $fileStream.Dispose()
    }
}

function Write-VulnHistoryDocument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        $HistoryDocument
    )

    $json = $HistoryDocument | ConvertTo-Json -Compress -Depth 100
    Write-GzipTextFile -Path $Path -Content $json
}

function Write-VulnHistoryRowsFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        $HistoryDocument
    )

    $fileStream = [System.IO.File]::Create($Path)
    try {
        $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Compress)
        try {
            $writer = [System.IO.StreamWriter]::new($gzipStream, [System.Text.UTF8Encoding]::new($false))
            try {
                foreach ($snapshot in @($HistoryDocument.snapshots)) {
                    if ($null -eq $snapshot) { continue }
                    foreach ($entry in @($snapshot.closed)) {
                        if ($null -eq $entry) { continue }
                        $row = Get-VulnPropertyValue -InputObject $entry -Name 'row'
                        if ($null -eq $row) { continue }
                        $writer.WriteLine(($row | ConvertTo-Json -Compress -Depth 20))
                    }
                }
            }
            finally {
                $writer.Dispose()
            }
        }
        finally {
            $gzipStream.Dispose()
        }
    }
    finally {
        $fileStream.Dispose()
    }
}

function Get-VulnHistoryFileLatestDate {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $prefix = Read-GzipTextFilePrefix -Path $Path -MaxChars 4096
    $latestMatch = [regex]::Match($prefix, '"latestDate"\s*:\s*"(?<date>\d{4}-\d{2}-\d{2})"')
    if ($latestMatch.Success) {
        return $latestMatch.Groups['date'].Value
    }

    $document = Read-VulnHistoryDocument -Path $Path
    return (Get-VulnHistoryDocumentLatestDate -HistoryDocument $document)
}

function Get-VulnHistoryDocumentLatestDate {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        $HistoryDocument
    )

    $latestDate = [string](Get-VulnPropertyValue -InputObject $HistoryDocument -Name 'latestDate')
    if (-not [string]::IsNullOrWhiteSpace($latestDate)) {
        return $latestDate
    }

    foreach ($snapshot in @($HistoryDocument.snapshots)) {
        $snapshotDate = Convert-VulnToYmdDate -DateValue (Get-VulnPropertyValue -InputObject $snapshot -Name 'date')
        if (-not [string]::IsNullOrWhiteSpace($snapshotDate)) {
            $latestDate = Get-MaxVulnDate -Primary $latestDate -Secondary $snapshotDate
        }
    }

    return $latestDate
}

function Add-VulnHistoryEntryToAppendStore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$AppendStateByPeriod,

        [Parameter(Mandatory = $true)]
        [string]$ScratchRoot,

        [Parameter(Mandatory = $true)]
        [string]$SnapshotDate,

        [Parameter(Mandatory = $true)]
        [string]$ClosedOn,

        [Parameter(Mandatory = $true)]
        $Entry
    )

    $periodKey = Get-VulnHistoryPeriodKeyFromDate -Date $ClosedOn
    if (-not $AppendStateByPeriod.ContainsKey($periodKey)) {
        $appendPath = Join-Path -Path $ScratchRoot -ChildPath ("VulnHistory_{0}.append.ndjson" -f $periodKey)
        $AppendStateByPeriod[$periodKey] = [PSCustomObject]@{
            AppendPath = $appendPath
            Writer = [System.IO.StreamWriter]::new($appendPath, $true, [System.Text.UTF8Encoding]::new($false))
            LatestDate = ''
        }
    }

    $state = $AppendStateByPeriod[$periodKey]
    $entryJson = $Entry | ConvertTo-Json -Compress -Depth 100
    $state.Writer.WriteLine($SnapshotDate + "`t" + $entryJson)
    $state.LatestDate = Get-MaxVulnDate -Primary ([string]$state.LatestDate) -Secondary $SnapshotDate
}

function Close-VulnHistoryAppendStore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$AppendStateByPeriod
    )

    foreach ($periodKey in @($AppendStateByPeriod.Keys)) {
        $state = $AppendStateByPeriod[$periodKey]
        if ($null -ne $state -and $null -ne $state.Writer) {
            $state.Writer.Dispose()
            $state.Writer = $null
        }
    }
}

function Write-VulnHistoryDocumentFromAppendFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$PeriodKey,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $ExistingDocument,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$AppendPath,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$LatestDate
    )

    $periodInfo = Get-VulnHistoryPeriodInfo -PeriodKey $PeriodKey
    $fileStream = [System.IO.File]::Create($Path)
    try {
        $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Compress)
        try {
            $writer = [System.IO.StreamWriter]::new($gzipStream, [System.Text.UTF8Encoding]::new($false))
            try {
                $writer.Write('{"year":')
                $writer.Write($periodInfo.Year)
                $writer.Write(',"quarter":')
                $writer.Write($periodInfo.Quarter)
                $writer.Write(',"period":')
                $writer.Write(($periodInfo.PeriodKey | ConvertTo-Json -Compress))
                $writer.Write(',"latestDate":')
                $writer.Write(($LatestDate | ConvertTo-Json -Compress))
                $writer.Write(',"snapshots":[')

                $existingSnapshots = if ($null -ne $ExistingDocument) {
                    @($ExistingDocument.snapshots)
                }
                else {
                    @()
                }

                $hasWrittenSnapshot = $false
                foreach ($snapshot in $existingSnapshots) {
                    if ($null -eq $snapshot) { continue }
                    if ($hasWrittenSnapshot) { $writer.Write(',') }
                    $writer.Write(($snapshot | ConvertTo-Json -Compress -Depth 100))
                    $hasWrittenSnapshot = $true
                }

                if (-not [string]::IsNullOrWhiteSpace($AppendPath) -and (Test-Path -LiteralPath $AppendPath -PathType Leaf)) {
                    $currentSnapshotDate = $null
                    $wroteClosedEntry = $false

                    foreach ($appendLine in Read-VulnNdjsonLinesFromPath -Path $AppendPath) {
                        $tabIndex = $appendLine.IndexOf("`t")
                        if ($tabIndex -lt 10) {
                            throw "Invalid vulnerability history append line in '$AppendPath'."
                        }

                        $snapshotDate = $appendLine.Substring(0, $tabIndex)
                        $entryJson = $appendLine.Substring($tabIndex + 1)

                        if ($currentSnapshotDate -ne $snapshotDate) {
                            if (-not [string]::IsNullOrWhiteSpace($currentSnapshotDate)) {
                                $writer.Write(']}')
                                $hasWrittenSnapshot = $true
                            }

                            if ($hasWrittenSnapshot) { $writer.Write(',') }
                            $writer.Write('{"date":')
                            $writer.Write(($snapshotDate | ConvertTo-Json -Compress))
                            $writer.Write(',"closed":[')
                            $currentSnapshotDate = $snapshotDate
                            $wroteClosedEntry = $false
                        }

                        if ($wroteClosedEntry) { $writer.Write(',') }
                        $writer.Write($entryJson)
                        $wroteClosedEntry = $true
                    }

                    if (-not [string]::IsNullOrWhiteSpace($currentSnapshotDate)) {
                        $writer.Write(']}')
                    }
                }

                $writer.Write(']}')
            }
            finally {
                $writer.Dispose()
            }
        }
        finally {
            $gzipStream.Dispose()
        }
    }
    finally {
        $fileStream.Dispose()
    }
}

function Write-VulnHistoryRowsFileFromAppendFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $ExistingDocument,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$AppendPath
    )

    $fileStream = [System.IO.File]::Create($Path)
    try {
        $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Compress)
        try {
            $writer = [System.IO.StreamWriter]::new($gzipStream, [System.Text.UTF8Encoding]::new($false))
            try {
                if ($null -ne $ExistingDocument) {
                    foreach ($snapshot in @($ExistingDocument.snapshots)) {
                        if ($null -eq $snapshot) { continue }
                        foreach ($entry in @($snapshot.closed)) {
                            if ($null -eq $entry) { continue }
                            $row = Get-VulnPropertyValue -InputObject $entry -Name 'row'
                            if ($null -eq $row) { continue }
                            $writer.WriteLine(($row | ConvertTo-Json -Compress -Depth 20))
                        }
                    }
                }

                if (-not [string]::IsNullOrWhiteSpace($AppendPath) -and (Test-Path -LiteralPath $AppendPath -PathType Leaf)) {
                    foreach ($appendLine in Read-VulnNdjsonLinesFromPath -Path $AppendPath) {
                        $tabIndex = $appendLine.IndexOf("`t")
                        if ($tabIndex -lt 10) {
                            throw "Invalid vulnerability history append line in '$AppendPath'."
                        }

                        $entryJson = $appendLine.Substring($tabIndex + 1)
                        $entry = $entryJson | ConvertFrom-Json -Depth 100
                        $row = Get-VulnPropertyValue -InputObject $entry -Name 'row'
                        if ($null -eq $row) { continue }
                        $writer.WriteLine(($row | ConvertTo-Json -Compress -Depth 20))
                    }
                }
            }
            finally {
                $writer.Dispose()
            }
        }
        finally {
            $gzipStream.Dispose()
        }
    }
    finally {
        $fileStream.Dispose()
    }
}

function Write-VulnHistoryRowsFileFromHistoryPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HistoryPath,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $fileStream = [System.IO.File]::Create($OutputPath)
    try {
        $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Compress)
        try {
            $writer = [System.IO.StreamWriter]::new($gzipStream, [System.Text.UTF8Encoding]::new($false))
            try {
                foreach ($row in Read-VulnHistoryRowsFromPath -Path $HistoryPath) {
                    if ($null -eq $row) { continue }
                    $writer.WriteLine(($row | ConvertTo-Json -Compress -Depth 20))
                }
            }
            finally {
                $writer.Dispose()
            }
        }
        finally {
            $gzipStream.Dispose()
        }
    }
    finally {
        $fileStream.Dispose()
    }
}

function Repair-VulnHistoryLayout {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    $historyFiles = @(Get-ChildItem -Path $BasePath -Filter 'VulnHistory_*.json.gz' -File -ErrorAction SilentlyContinue | Sort-Object Name)
    if ($historyFiles.Count -eq 0) {
        return 0
    }

    $canonicalDocumentsByPeriod = @{}
    foreach ($historyFile in $historyFiles) {
        $sourceDocument = Read-VulnHistoryDocument -Path $historyFile.FullName
        $sourcePeriodKey = Get-VulnHistoryPeriodKeyFromDocument -HistoryDocument $sourceDocument
        $sourceIsCanonical = -not [string]::IsNullOrWhiteSpace($sourcePeriodKey)

        foreach ($historyDocument in Convert-VulnHistoryDocumentToQuarterlyDocuments -HistoryDocument $sourceDocument) {
            $periodKey = Get-VulnHistoryPeriodKeyFromDocument -HistoryDocument $historyDocument
            if ([string]::IsNullOrWhiteSpace($periodKey)) { continue }

            $shouldReplace = -not $canonicalDocumentsByPeriod.ContainsKey($periodKey)
            if (-not $shouldReplace -and $sourceIsCanonical) {
                $shouldReplace = $true
            }

            if ($shouldReplace) {
                $canonicalDocumentsByPeriod[$periodKey] = $historyDocument
            }
        }
    }

    if ($canonicalDocumentsByPeriod.Count -eq 0) {
        return 0
    }

    $stageRoot = Join-Path $BasePath ('.vuln-history-layout-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $stageRoot -ItemType Directory -Force)

    try {
        $filesToPublish = [System.Collections.Generic.List[object]]::new()
        $publishedHistoryNames = if ($canonicalDocumentsByPeriod.Count -gt 0) {
            Get-VulnHistoryPublishedNameSet -PeriodKeys @($canonicalDocumentsByPeriod.Keys)
        }
        else {
            [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        }

        foreach ($periodKey in @($canonicalDocumentsByPeriod.Keys | Sort-Object)) {
            $historyDocument = $canonicalDocumentsByPeriod[$periodKey]
            $historyStagePath = Get-VulnHistoryPath -BasePath $stageRoot -PeriodKey $periodKey
            Write-VulnHistoryDocument -Path $historyStagePath -HistoryDocument $historyDocument
            $historyRowsStagePath = Get-VulnHistoryRowsPath -BasePath $stageRoot -PeriodKey $periodKey
            Write-VulnHistoryRowsFile -Path $historyRowsStagePath -HistoryDocument $historyDocument

            $filesToPublish.Add([PSCustomObject]@{
                StagePath = $historyStagePath
                TargetPath = Get-VulnHistoryPath -BasePath $BasePath -PeriodKey $periodKey
            })
            $filesToPublish.Add([PSCustomObject]@{
                StagePath = $historyRowsStagePath
                TargetPath = Get-VulnHistoryRowsPath -BasePath $BasePath -PeriodKey $periodKey
            })
        }

        $historyFilesToRemove = Get-VulnHistoryRemovePaths -BasePath $BasePath -PublishedHistoryNames $publishedHistoryNames
        Publish-StoreFilesTransactional -BasePath $BasePath -StoreName 'vuln' -Files @($filesToPublish) -RemovePaths $historyFilesToRemove
        return $canonicalDocumentsByPeriod.Count
    }
    finally {
        if (Test-Path -LiteralPath $stageRoot) {
            Remove-Item -LiteralPath $stageRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-VulnPartitionIndex {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id,

        [Parameter(Mandatory = $false)]
        [int]$PartitionCount = $Script:VulnDiskPartitionCount
    )

    $hash = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($Id))
    return ([int]$hash[0]) % $PartitionCount
}

function Get-VulnPartitionFilePath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root,

        [Parameter(Mandatory = $true)]
        [string]$Prefix,

        [Parameter(Mandatory = $true)]
        [int]$Index
    )

    return Join-Path -Path $Root -ChildPath ("{0}-{1:D2}.ndjson" -f $Prefix, $Index)
}

function Split-VulnJsonPartition {
    [CmdletBinding()]
    [OutputType([int[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$InputPaths,

        [Parameter(Mandatory = $true)]
        [string]$OutputRoot,

        [Parameter(Mandatory = $true)]
        [string]$Prefix,

        [Parameter(Mandatory = $false)]
        [switch]$OnboardedOnly,

        [Parameter(Mandatory = $false)]
        [int]$PartitionCount = $Script:VulnDiskPartitionCount
    )

    [void](New-Item -Path $OutputRoot -ItemType Directory -Force)

    $writers = @{}
    $writtenIndexes = [System.Collections.Generic.HashSet[int]]::new()
    try {
        foreach ($inputPath in @($InputPaths)) {
            if ([string]::IsNullOrWhiteSpace($inputPath) -or -not (Test-Path -LiteralPath $inputPath -PathType Leaf)) { continue }

            foreach ($jsonLine in Read-VulnNdjsonLinesFromPath -Path $inputPath) {
                $record = $jsonLine | ConvertFrom-Json -Depth 20
                $id = [string](Get-VulnPropertyValue -InputObject $record -Name 'Id')
                if ([string]::IsNullOrWhiteSpace($id)) { continue }
                if ($OnboardedOnly -and (Get-VulnPropertyValue -InputObject $record -Name 'IsOnboarded') -ne $true) { continue }

                $partitionIndex = Get-VulnPartitionIndex -Id $id -PartitionCount $PartitionCount
                if (-not $writers.ContainsKey($partitionIndex)) {
                    $partitionPath = Get-VulnPartitionFilePath -Root $OutputRoot -Prefix $Prefix -Index $partitionIndex
                    $writers[$partitionIndex] = [System.IO.StreamWriter]::new($partitionPath, $true, [System.Text.UTF8Encoding]::new($false))
                }

                $writers[$partitionIndex].WriteLine($jsonLine)
                [void]$writtenIndexes.Add($partitionIndex)
            }
        }
    }
    finally {
        foreach ($writer in @($writers.Values)) {
            if ($null -ne $writer) {
                $writer.Dispose()
            }
        }
    }

    return @($writtenIndexes | Sort-Object)
}

function Read-VulnPartitionMapFile {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $rows = @{}
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $rows
    }

    foreach ($jsonLine in Read-VulnNdjsonLinesFromPath -Path $Path) {
        $record = $jsonLine | ConvertFrom-Json -Depth 20
        $id = [string](Get-VulnPropertyValue -InputObject $record -Name 'Id')
        if ([string]::IsNullOrWhiteSpace($id)) { continue }

        $versionStartDate = Convert-VulnToYmdDate -DateValue (Get-VulnPropertyValue -InputObject $record -Name 'FirstSeenTimestamp')
        $rows[$id] = [PSCustomObject]@{
            Json = $jsonLine
            Signature = Get-VulnCanonicalRowSignature -Row $record
            VersionStartDate = $versionStartDate
        }
    }

    return $rows
}

function Write-VulnPartitionMapFile {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [hashtable]$RowsById
    )

    if ($RowsById.Count -eq 0) {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        }
        return 0
    }

    $writer = [System.IO.StreamWriter]::new($Path, $false, [System.Text.UTF8Encoding]::new($false))
    try {
        $rowCount = 0
        foreach ($id in @($RowsById.Keys | Sort-Object)) {
            $writer.WriteLine([string]$RowsById[$id].Json)
            $rowCount++
        }
        return $rowCount
    }
    finally {
        $writer.Dispose()
    }
}

function Write-VulnCurrentFileFromPartition {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PartitionRoot,

        [Parameter(Mandatory = $true)]
        [string]$PartitionPrefix,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [int]$PartitionCount = $Script:VulnDiskPartitionCount
    )

    $fileStream = [System.IO.File]::Create($OutputPath)
    try {
        $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Compress)
        try {
            $writer = [System.IO.StreamWriter]::new($gzipStream, [System.Text.UTF8Encoding]::new($false))
            try {
                $rowCount = 0
                for ($partitionIndex = 0; $partitionIndex -lt $PartitionCount; $partitionIndex++) {
                    $partitionPath = Get-VulnPartitionFilePath -Root $PartitionRoot -Prefix $PartitionPrefix -Index $partitionIndex
                    if (-not (Test-Path -LiteralPath $partitionPath -PathType Leaf)) { continue }

                    foreach ($jsonLine in Read-VulnNdjsonLinesFromPath -Path $partitionPath) {
                        $writer.WriteLine($jsonLine)
                        $rowCount++
                    }
                }

                return $rowCount
            }
            finally {
                $writer.Dispose()
            }
        }
        finally {
            $gzipStream.Dispose()
        }
    }
    finally {
        $fileStream.Dispose()
    }
}

function Publish-VulnStoreUnlocked {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $true)]
        $Store
    )

    $storeToPublish = $Store

    $stageRoot = Join-Path $BasePath ('.vuln-store-staging-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $stageRoot -ItemType Directory -Force)

    try {
        $stagedCurrentPath = Get-VulnCurrentPath -BasePath $stageRoot
        Write-VulnCurrentFile -Path $stagedCurrentPath -Records $storeToPublish.CurrentRecords
        Write-Information ("  Vulnerability store publish: {0} current row(s), {1} history period(s)" -f @($storeToPublish.CurrentRecords).Count, @($storeToPublish.HistoryDocuments).Count) -InformationAction Continue

        foreach ($historyDocument in @($storeToPublish.HistoryDocuments)) {
            $periodKey = Get-VulnHistoryPeriodKeyFromDocument -HistoryDocument $historyDocument
            $historyPath = Get-VulnHistoryPath -BasePath $stageRoot -PeriodKey $periodKey
            Write-VulnHistoryDocument -Path $historyPath -HistoryDocument $historyDocument
            $historyRowsPath = Get-VulnHistoryRowsPath -BasePath $stageRoot -PeriodKey $periodKey
            Write-VulnHistoryRowsFile -Path $historyRowsPath -HistoryDocument $historyDocument
        }

        $currentCount = Test-VulnCurrentFile -Path $stagedCurrentPath
        foreach ($historyFile in Get-ChildItem -Path $stageRoot -Filter 'VulnHistory_*.json.gz' -File -ErrorAction SilentlyContinue) {
            [void](Test-VulnHistoryFileLightweight -Path $historyFile.FullName)
        }

        $filesToPublish = [System.Collections.Generic.List[object]]::new()
        $filesToPublish.Add([PSCustomObject]@{
            StagePath = $stagedCurrentPath
            TargetPath = Get-VulnCurrentPath -BasePath $BasePath
        })

        $historyPeriodKeys = @(
            @($storeToPublish.HistoryDocuments) | ForEach-Object {
                Get-VulnHistoryPeriodKeyFromDocument -HistoryDocument $_
            }
        )
        $publishedHistoryNames = if ($historyPeriodKeys.Count -gt 0) {
            Get-VulnHistoryPublishedNameSet -PeriodKeys $historyPeriodKeys
        }
        else {
            [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        }
        foreach ($historyDocument in @($storeToPublish.HistoryDocuments)) {
            $periodKey = Get-VulnHistoryPeriodKeyFromDocument -HistoryDocument $historyDocument
            $historyName = [string]::Format($Script:VulnHistoryFileNamePattern, $periodKey)
            $filesToPublish.Add([PSCustomObject]@{
                StagePath = Join-Path $stageRoot $historyName
                TargetPath = Join-Path $BasePath $historyName
            })

            $historyRowsName = [string]::Format($Script:VulnHistoryRowsFileNamePattern, $periodKey)
            $filesToPublish.Add([PSCustomObject]@{
                StagePath = Join-Path $stageRoot $historyRowsName
                TargetPath = Join-Path $BasePath $historyRowsName
            })
        }

        $historyFilesToRemove = Get-VulnHistoryRemovePaths -BasePath $BasePath -PublishedHistoryNames $publishedHistoryNames
        Publish-StoreFilesTransactional -BasePath $BasePath -StoreName 'vuln' -Files @($filesToPublish) -RemovePaths $historyFilesToRemove
        $historyPeriodCount = Repair-VulnHistoryLayout -BasePath $BasePath

        return [PSCustomObject]@{
            CurrentRows = $currentCount
            HistoryYears = if ($historyPeriodCount -gt 0) { $historyPeriodCount } else { @($storeToPublish.HistoryDocuments).Count }
            LatestSnapshotDate = $storeToPublish.LatestSnapshotDate
        }
    }
    finally {
        if (Test-Path -Path $stageRoot) {
            Remove-Item -Path $stageRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Publish-VulnStore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $true)]
        $Store
    )

    $storeToPublish = $Store

    return Invoke-WithStoreLock -BasePath $BasePath -StoreName 'vuln' -ScriptBlock {
        Restore-StoreTransaction -BasePath $BasePath -StoreName 'vuln'
        Publish-VulnStoreUnlocked -BasePath $BasePath -Store $storeToPublish
    }
}
