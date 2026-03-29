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
$Script:VulnContentDictionaryFileName = 'VulnContentDictionary.json.gz'
$Script:VulnCurrentRefsFileName = 'VulnCurrentRefs.json.gz'
$Script:VulnHistoryRefsFileNamePattern = 'VulnHistoryRefs_{0}.json.gz'
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

function Get-VulnContentDictionaryPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    return Join-Path -Path $BasePath -ChildPath $Script:VulnContentDictionaryFileName
}

function Get-VulnCurrentRefsPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    return Join-Path -Path $BasePath -ChildPath $Script:VulnCurrentRefsFileName
}

function Get-VulnHistoryRefsPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $true)]
        [string]$PeriodKey
    )

    return Join-Path -Path $BasePath -ChildPath ([string]::Format($Script:VulnHistoryRefsFileNamePattern, $PeriodKey))
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

function Test-VulnContentStoreExistence {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    $dictionaryPath = Get-VulnContentDictionaryPath -BasePath $BasePath
    if (-not (Test-Path -LiteralPath $dictionaryPath -PathType Leaf)) {
        return $false
    }

    $currentRefsPath = Get-VulnCurrentRefsPath -BasePath $BasePath
    if (-not (Test-Path -LiteralPath $currentRefsPath -PathType Leaf)) {
        return $false
    }

    $historyPeriodKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($historyRowsFile in @(Get-ChildItem -Path $BasePath -Filter 'VulnHistoryRows_*.json.gz' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
        $match = [regex]::Match($historyRowsFile.Name, '^VulnHistoryRows_(?<period>\d{4}Q[1-4]|\d{4})\.json\.gz$')
        if (-not $match.Success) { continue }
        [void]$historyPeriodKeys.Add($match.Groups['period'].Value)
    }

    foreach ($historyFile in @(Get-ChildItem -Path $BasePath -Filter 'VulnHistory_*.json.gz' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
        $match = [regex]::Match($historyFile.Name, '^VulnHistory_(?<period>\d{4}Q[1-4]|\d{4})\.json\.gz$')
        if (-not $match.Success) { continue }
        [void]$historyPeriodKeys.Add($match.Groups['period'].Value)
    }

    foreach ($periodKey in @($historyPeriodKeys | Sort-Object)) {
        $historyRefsPath = Get-VulnHistoryRefsPath -BasePath $BasePath -PeriodKey $periodKey
        if (-not (Test-Path -LiteralPath $historyRefsPath -PathType Leaf)) {
            return $false
        }
    }

    return $true
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

function Test-IsVulnHistoryRefsFileName {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    return ($Name -match '^VulnHistoryRefs_(?:\d{4}Q[1-4]|\d{4})\.json\.gz$')
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
        [void]$publishedNames.Add([string]::Format($Script:VulnHistoryRefsFileNamePattern, $periodKey))
    }

    return ,$publishedNames
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

    foreach ($path in @(
        Get-ChildItem -Path $BasePath -Filter 'VulnHistoryRefs_*.json.gz' -File -ErrorAction SilentlyContinue |
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
        $Script:VulnContentDictionaryFileName,
        $Script:VulnCurrentRefsFileName,
        $Script:MachineCurrentFileName,
        $Script:AdvancedHuntingCurrentFileName
    )) {
        return $true
    }

    if ((Test-IsVulnHistoryFileName -Name $Name) -or (Test-IsVulnHistoryRowsFileName -Name $Name) -or (Test-IsVulnHistoryRefsFileName -Name $Name)) {
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

function Resolve-RelativeExportArtifactName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $normalizedName = $Name.Replace('\', '/')
    while ($normalizedName.StartsWith('./', [System.StringComparison]::Ordinal)) {
        $normalizedName = $normalizedName.Substring(2)
    }

    return $normalizedName
}

function Test-IsExportTransferArtifactName {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $normalizedName = Resolve-RelativeExportArtifactName -Name $Name
    if ([string]::IsNullOrWhiteSpace($normalizedName)) {
        return $false
    }

    return (
        (Test-IsCanonicalExportStoreFileName -Name $normalizedName) -or
        ($normalizedName -eq 'synthetic-manifest.json')
    )
}

function Test-IsTransientExportArtifactName {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $normalizedName = Resolve-RelativeExportArtifactName -Name $Name
    if ([string]::IsNullOrWhiteSpace($normalizedName)) {
        return $false
    }

    return (
        ($normalizedName -like '.dashboard-cache/*') -or
        ($normalizedName -match '(^|/)\.vuln-content-store-staging-[^/]+(?:/|$)') -or
        ($normalizedName -in @(
            '.synthetic-progress.json',
            '.synthetic-progress.json.gz',
            'stress-validation-report.json',
            'stress-validation-report.json.gz'
        ))
    )
}

function Get-ExportTransferArtifactNames {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    $names = [System.Collections.Generic.List[string]]::new()
    foreach ($name in @(Get-CanonicalExportStoreFileNames -BasePath $BasePath)) {
        if (-not [string]::IsNullOrWhiteSpace($name)) {
            $names.Add($name)
        }
    }

    $syntheticManifestPath = Join-Path -Path $BasePath -ChildPath 'synthetic-manifest.json'
    if (Test-Path -LiteralPath $syntheticManifestPath -PathType Leaf) {
        $names.Add('synthetic-manifest.json')
    }

    return [string[]]@($names | Sort-Object -Unique)
}

function Clear-StaleLocalExportArtifact {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $false)]
        [string[]]$KeepNames = @()
    )

    if (-not (Test-Path -LiteralPath $BasePath -PathType Container)) {
        return
    }

    $keepNameSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($name in @($KeepNames)) {
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        [void]$keepNameSet.Add((Resolve-RelativeExportArtifactName -Name $name))
    }

    $pathsToRemove = [System.Collections.Generic.List[string]]::new()
    foreach ($item in @(Get-ChildItem -Path $BasePath -Force -Recurse -ErrorAction SilentlyContinue | Sort-Object FullName -Descending)) {
        $relativeName = [System.IO.Path]::GetRelativePath($BasePath, $item.FullName).Replace('\', '/')
        if ($keepNameSet.Contains($relativeName)) {
            continue
        }

        if ($item.PSIsContainer) {
            if (Test-IsTransientExportArtifactName -Name ($relativeName + '/')) {
                $pathsToRemove.Add($item.FullName)
            }
            continue
        }

        if ((Test-IsTransientExportArtifactName -Name $relativeName) -or ((Test-IsExportTransferArtifactName -Name $relativeName) -and -not $keepNameSet.Contains($relativeName))) {
            $pathsToRemove.Add($item.FullName)
        }
    }

    foreach ($path in @($pathsToRemove | Sort-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $path)) {
            continue
        }

        $item = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        if ($null -eq $item) {
            continue
        }

        if ($item.PSIsContainer) {
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
        }
        else {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
    }
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
            (Test-IsExportTransferArtifactName -Name $name) -or
            (Test-IsTransientExportArtifactName -Name $name) -or
            (Test-IsVulnHistoryFileName -Name $name) -or
            (Test-IsVulnHistoryRowsFileName -Name $name) -or
            (Test-IsVulnHistoryRefsFileName -Name $name) -or
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
            $buffer = New-Object byte[] 65536
            $carryStream = [System.IO.MemoryStream]::new()
            try {
                while (($bytesRead = $contentStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $segmentStart = 0
                    for ($index = 0; $index -lt $bytesRead; $index++) {
                        if ($buffer[$index] -ne 0x0A) { continue }

                        $segmentLength = $index - $segmentStart
                        if ($segmentLength -gt 0 -and $buffer[$index - 1] -eq 0x0D) {
                            $segmentLength--
                        }

                        if ($carryStream.Length -gt 0) {
                            if ($segmentLength -gt 0) {
                                $carryStream.Write($buffer, $segmentStart, $segmentLength)
                            }

                            if ($carryStream.Length -gt 0) {
                                $line = [System.Text.Encoding]::UTF8.GetString($carryStream.ToArray())
                                if (-not [string]::IsNullOrWhiteSpace($line)) {
                                    Write-Output $line
                                }
                            }

                            $carryStream.SetLength(0)
                        }
                        elseif ($segmentLength -gt 0) {
                            $line = [System.Text.Encoding]::UTF8.GetString($buffer, $segmentStart, $segmentLength)
                            if (-not [string]::IsNullOrWhiteSpace($line)) {
                                Write-Output $line
                            }
                        }

                        $segmentStart = $index + 1
                    }

                    $remainingLength = $bytesRead - $segmentStart
                    if ($remainingLength -gt 0) {
                        $carryStream.Write($buffer, $segmentStart, $remainingLength)
                    }
                }

                if ($carryStream.Length -gt 0) {
                    $lineBytes = $carryStream.ToArray()
                    $lineLength = $lineBytes.Length
                    if ($lineLength -gt 0 -and $lineBytes[$lineLength - 1] -eq 0x0D) {
                        $lineLength--
                    }

                    if ($lineLength -gt 0) {
                        $line = [System.Text.Encoding]::UTF8.GetString($lineBytes, 0, $lineLength)
                        if (-not [string]::IsNullOrWhiteSpace($line)) {
                            Write-Output $line
                        }
                    }
                }
            }
            finally {
                $carryStream.Dispose()
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

function Invoke-VulnNdjsonLineAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Action
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
            $buffer = New-Object byte[] 65536
            $carryStream = [System.IO.MemoryStream]::new()
            try {
                while (($bytesRead = $contentStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $segmentStart = 0
                    for ($index = 0; $index -lt $bytesRead; $index++) {
                        if ($buffer[$index] -ne 0x0A) { continue }

                        $segmentLength = $index - $segmentStart
                        if ($segmentLength -gt 0 -and $buffer[$index - 1] -eq 0x0D) {
                            $segmentLength--
                        }

                        $line = $null
                        if ($carryStream.Length -gt 0) {
                            if ($segmentLength -gt 0) {
                                $carryStream.Write($buffer, $segmentStart, $segmentLength)
                            }

                            if ($carryStream.Length -gt 0) {
                                $line = [System.Text.Encoding]::UTF8.GetString($carryStream.ToArray())
                            }
                            $carryStream.SetLength(0)
                        }
                        elseif ($segmentLength -gt 0) {
                            $line = [System.Text.Encoding]::UTF8.GetString($buffer, $segmentStart, $segmentLength)
                        }

                        if (-not [string]::IsNullOrWhiteSpace($line)) {
                            & $Action $line
                        }

                        $segmentStart = $index + 1
                    }

                    $remainingLength = $bytesRead - $segmentStart
                    if ($remainingLength -gt 0) {
                        $carryStream.Write($buffer, $segmentStart, $remainingLength)
                    }
                }

                if ($carryStream.Length -gt 0) {
                    $lineBytes = $carryStream.ToArray()
                    $lineLength = $lineBytes.Length
                    if ($lineLength -gt 0 -and $lineBytes[$lineLength - 1] -eq 0x0D) {
                        $lineLength--
                    }

                    if ($lineLength -gt 0) {
                        $line = [System.Text.Encoding]::UTF8.GetString($lineBytes, 0, $lineLength)
                        if (-not [string]::IsNullOrWhiteSpace($line)) {
                            & $Action $line
                        }
                    }
                }
            }
            finally {
                $carryStream.Dispose()
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

function Invoke-VulnNdjsonJsonRootAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Action
    )

    $rootAction = $Action

    Invoke-VulnNdjsonLineAction -Path $Path -Action {
        param([string]$JsonLine)

        $document = [System.Text.Json.JsonDocument]::Parse($JsonLine)
        try {
            & $rootAction $document.RootElement
        }
        finally {
            $document.Dispose()
        }
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
        Publish-VulnContentStoreUnlocked -BasePath $BasePath

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

function Get-VulnDeviceProfileSignature {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        $Row
    )

    $machineTags = @((Get-VulnPropertyValue -InputObject $Row -Name 'MachineTags'))
    $valueDelimiter = [string][char]0x001f
    $listDelimiter = [string][char]0x001e
    return @(
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'DeviceId')
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'DeviceName')
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'RbacGroupName')
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'OSPlatform')
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'OSVersion')
        ($machineTags -join $listDelimiter)
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'IsOnboarded')
    ) -join $valueDelimiter
}

function Get-VulnContentTemplateSignature {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        $Row
    )

    $diskPaths = @((Get-VulnPropertyValue -InputObject $Row -Name 'DiskPaths'))
    $registryPaths = @((Get-VulnPropertyValue -InputObject $Row -Name 'RegistryPaths'))

    $valueDelimiter = [string][char]0x001f
    $listDelimiter = [string][char]0x001e
    return @(
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'CveId')
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'SoftwareVendor')
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'SoftwareName')
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'SoftwareVersion')
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'VulnerabilitySeverityLevel')
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'CvssScore')
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'ExploitabilityLevel')
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'RecommendationReference')
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'RecommendedSecurityUpdate')
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'RecommendedSecurityUpdateId')
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'RecommendedSecurityUpdateUrl')
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'SecurityUpdateAvailable')
        ($diskPaths -join $listDelimiter)
        ($registryPaths -join $listDelimiter)
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'CveBatchTitle')
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'CveBatchUrl')
    ) -join $valueDelimiter
}

function ConvertTo-VulnDeviceProfileTemplate {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        $Row
    )

    return [PSCustomObject]@{
        id = [string](Get-VulnPropertyValue -InputObject $Row -Name 'DeviceId')
        n = [string](Get-VulnPropertyValue -InputObject $Row -Name 'DeviceName')
        g = [string](Get-VulnPropertyValue -InputObject $Row -Name 'RbacGroupName')
        o = [string](Get-VulnPropertyValue -InputObject $Row -Name 'OSPlatform')
        ov = [string](Get-VulnPropertyValue -InputObject $Row -Name 'OSVersion')
        t = @((Get-VulnPropertyValue -InputObject $Row -Name 'MachineTags'))
        ob = ((Get-VulnPropertyValue -InputObject $Row -Name 'IsOnboarded') -eq $true)
    }
}

function ConvertTo-VulnContentTemplate {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        $Row
    )

    return [PSCustomObject]@{
        c = [string](Get-VulnPropertyValue -InputObject $Row -Name 'CveId')
        sv = [string](Get-VulnPropertyValue -InputObject $Row -Name 'SoftwareVendor')
        sn = [string](Get-VulnPropertyValue -InputObject $Row -Name 'SoftwareName')
        ver = [string](Get-VulnPropertyValue -InputObject $Row -Name 'SoftwareVersion')
        sev = [string](Get-VulnPropertyValue -InputObject $Row -Name 'VulnerabilitySeverityLevel')
        sc = (Get-VulnPropertyValue -InputObject $Row -Name 'CvssScore')
        ex = [string](Get-VulnPropertyValue -InputObject $Row -Name 'ExploitabilityLevel')
        rr = [string](Get-VulnPropertyValue -InputObject $Row -Name 'RecommendationReference')
        ru = [string](Get-VulnPropertyValue -InputObject $Row -Name 'RecommendedSecurityUpdate')
        rid = [string](Get-VulnPropertyValue -InputObject $Row -Name 'RecommendedSecurityUpdateId')
        url = [string](Get-VulnPropertyValue -InputObject $Row -Name 'RecommendedSecurityUpdateUrl')
        ua = ((Get-VulnPropertyValue -InputObject $Row -Name 'SecurityUpdateAvailable') -eq $true)
        dp = @((Get-VulnPropertyValue -InputObject $Row -Name 'DiskPaths'))
        rp = @((Get-VulnPropertyValue -InputObject $Row -Name 'RegistryPaths'))
        bt = [string](Get-VulnPropertyValue -InputObject $Row -Name 'CveBatchTitle')
        bu = [string](Get-VulnPropertyValue -InputObject $Row -Name 'CveBatchUrl')
    }
}

function Convert-ToJsonStringLiteral {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Value
    )

    if ($null -eq $Value) {
        return 'null'
    }

    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.Append('"')
    foreach ($character in $Value.ToCharArray()) {
        switch ($character) {
            '"' { [void]$builder.Append('\"') }
            '\' { [void]$builder.Append('\\') }
            "`b" { [void]$builder.Append('\b') }
            "`f" { [void]$builder.Append('\f') }
            "`n" { [void]$builder.Append('\n') }
            "`r" { [void]$builder.Append('\r') }
            "`t" { [void]$builder.Append('\t') }
            default {
                if ([int][char]$character -lt 32) {
                    [void]$builder.Append('\u')
                    [void]$builder.Append(([int][char]$character).ToString('x4'))
                }
                else {
                    [void]$builder.Append($character)
                }
            }
        }
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Write-VulnObservationRefLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.StreamWriter]$Writer,

        [Parameter(Mandatory = $true)]
        [string]$Id,

        [Parameter(Mandatory = $true)]
        [int]$DeviceProfileIndex,

        [Parameter(Mandatory = $true)]
        [int]$ContentTemplateIndex,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$FirstSeenTimestamp,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$LastSeenTimestamp
    )

    $Writer.WriteLine((
        '[' +
        (Convert-ToJsonStringLiteral -Value $Id) + ',' +
        $DeviceProfileIndex + ',' +
        $ContentTemplateIndex + ',' +
        (Convert-ToJsonStringLiteral -Value $FirstSeenTimestamp) + ',' +
        (Convert-ToJsonStringLiteral -Value $LastSeenTimestamp) +
        ']'
    ))
}

function Read-VulnContentDictionary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return (Read-GzipTextFile -Path $Path | ConvertFrom-Json -Depth 20)
}

function Read-VulnContentStoreRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    $dictionary = Read-VulnContentDictionary -Path (Get-VulnContentDictionaryPath -BasePath $BasePath)
    $refPaths = [System.Collections.Generic.List[string]]::new()

    $currentRefsPath = Get-VulnCurrentRefsPath -BasePath $BasePath
    if (Test-Path -LiteralPath $currentRefsPath -PathType Leaf) {
        $refPaths.Add($currentRefsPath)
    }

    foreach ($historyRefsFile in @(Get-ChildItem -Path $BasePath -Filter 'VulnHistoryRefs_*.json.gz' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
        $refPaths.Add($historyRefsFile.FullName)
    }

    foreach ($refPath in $refPaths) {
        foreach ($line in Read-VulnNdjsonLinesFromPath -Path $refPath) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }

            $ref = $line | ConvertFrom-Json -Depth 10
            $device = $dictionary.deviceProfiles[[int]$ref[1]]
            $content = $dictionary.contentTemplates[[int]$ref[2]]

            Write-Output ([PSCustomObject]@{
                Id = [string]$ref[0]
                DeviceId = [string]$device.id
                DeviceName = [string]$device.n
                RbacGroupName = [string]$device.g
                OSPlatform = [string]$device.o
                OSVersion = [string]$device.ov
                MachineTags = @($device.t)
                CveId = [string]$content.c
                SoftwareVendor = [string]$content.sv
                SoftwareName = [string]$content.sn
                SoftwareVersion = [string]$content.ver
                VulnerabilitySeverityLevel = [string]$content.sev
                CvssScore = $content.sc
                ExploitabilityLevel = [string]$content.ex
                RecommendationReference = [string]$content.rr
                RecommendedSecurityUpdate = [string]$content.ru
                RecommendedSecurityUpdateId = [string]$content.rid
                RecommendedSecurityUpdateUrl = [string]$content.url
                SecurityUpdateAvailable = ($content.ua -eq $true)
                FirstSeenTimestamp = [string]$ref[3]
                LastSeenTimestamp = [string]$ref[4]
                DiskPaths = @($content.dp)
                RegistryPaths = @($content.rp)
                CveBatchTitle = [string]$content.bt
                CveBatchUrl = [string]$content.bu
                IsOnboarded = ($device.ob -eq $true)
            })
        }
    }
}

function Publish-VulnContentStoreUnlocked {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    if (-not (Test-VulnStoreExistence -BasePath $BasePath)) {
        return
    }

    $stageRoot = Join-Path $BasePath ('.vuln-content-store-staging-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $stageRoot -ItemType Directory -Force)

    try {
        $deviceProfiles = [System.Collections.Generic.List[object]]::new()
        $deviceProfileIndex = @{}
        $contentTemplates = [System.Collections.Generic.List[object]]::new()
        $contentTemplateIndex = @{}
        $filesToPublish = [System.Collections.Generic.List[object]]::new()

        $writeObservationRefs = {
            param(
                [string]$InputPath,
                [string]$OutputPath
            )

            $fileStream = $null
            $gzipStream = $null
            $writer = $null
            try {
                $fileStream = [System.IO.File]::Create($OutputPath)
                $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Compress)
                $writer = [System.IO.StreamWriter]::new($gzipStream, [System.Text.UTF8Encoding]::new($false))

                foreach ($row in Read-VulnNdjsonRecordsFromPath -Path $InputPath) {
                    if ($null -eq $row) { continue }

                    $deviceSignature = Get-VulnDeviceProfileSignature -Row $row
                    if (-not $deviceProfileIndex.ContainsKey($deviceSignature)) {
                        $deviceProfileIndex[$deviceSignature] = $deviceProfiles.Count
                        [void]$deviceProfiles.Add((ConvertTo-VulnDeviceProfileTemplate -Row $row))
                    }
                    $deviceIndexValue = [int]$deviceProfileIndex[$deviceSignature]

                    $contentSignature = Get-VulnContentTemplateSignature -Row $row
                    if (-not $contentTemplateIndex.ContainsKey($contentSignature)) {
                        $contentTemplateIndex[$contentSignature] = $contentTemplates.Count
                        [void]$contentTemplates.Add((ConvertTo-VulnContentTemplate -Row $row))
                    }
                    $contentIndexValue = [int]$contentTemplateIndex[$contentSignature]

                    Write-VulnObservationRefLine `
                        -Writer $writer `
                        -Id ([string](Get-VulnPropertyValue -InputObject $row -Name 'Id')) `
                        -DeviceProfileIndex $deviceIndexValue `
                        -ContentTemplateIndex $contentIndexValue `
                        -FirstSeenTimestamp ([string](Get-VulnPropertyValue -InputObject $row -Name 'FirstSeenTimestamp')) `
                        -LastSeenTimestamp ([string](Get-VulnPropertyValue -InputObject $row -Name 'LastSeenTimestamp'))
                }
            }
            finally {
                if ($writer) { $writer.Dispose() }
                elseif ($gzipStream) { $gzipStream.Dispose() }
                elseif ($fileStream) { $fileStream.Dispose() }
            }
        }

        $currentPath = Get-VulnCurrentPath -BasePath $BasePath
        if (Test-Path -LiteralPath $currentPath -PathType Leaf) {
            $stagedCurrentRefsPath = Get-VulnCurrentRefsPath -BasePath $stageRoot
            & $writeObservationRefs $currentPath $stagedCurrentRefsPath
            [void]$filesToPublish.Add([PSCustomObject]@{
                StagePath = $stagedCurrentRefsPath
                TargetPath = Get-VulnCurrentRefsPath -BasePath $BasePath
            })
        }

        $periodKeys = [System.Collections.Generic.List[string]]::new()
        foreach ($historyRowsFile in @(Get-ChildItem -Path $BasePath -Filter 'VulnHistoryRows_*.json.gz' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
            $match = [regex]::Match($historyRowsFile.Name, '^VulnHistoryRows_(?<period>\d{4}Q[1-4]|\d{4})\.json\.gz$')
            if (-not $match.Success) { continue }

            $periodKey = [string]$match.Groups['period'].Value
            [void]$periodKeys.Add($periodKey)
            $stagedHistoryRefsPath = Get-VulnHistoryRefsPath -BasePath $stageRoot -PeriodKey $periodKey
            & $writeObservationRefs $historyRowsFile.FullName $stagedHistoryRefsPath
            [void]$filesToPublish.Add([PSCustomObject]@{
                StagePath = $stagedHistoryRefsPath
                TargetPath = Get-VulnHistoryRefsPath -BasePath $BasePath -PeriodKey $periodKey
            })
        }

        $dictionaryPath = Get-VulnContentDictionaryPath -BasePath $stageRoot
        $dictionaryJson = [PSCustomObject]@{
            version = 'content-dictionary-v1'
            deviceProfiles = @($deviceProfiles)
            contentTemplates = @($contentTemplates)
        } | ConvertTo-Json -Compress -Depth 20
        $dictionaryFileStream = $null
        $dictionaryGzipStream = $null
        $dictionaryWriter = $null
        try {
            $dictionaryFileStream = [System.IO.File]::Create($dictionaryPath)
            $dictionaryGzipStream = [System.IO.Compression.GZipStream]::new($dictionaryFileStream, [System.IO.Compression.CompressionMode]::Compress)
            $dictionaryWriter = [System.IO.StreamWriter]::new($dictionaryGzipStream, [System.Text.UTF8Encoding]::new($false))
            $dictionaryWriter.Write($dictionaryJson)
        }
        finally {
            if ($dictionaryWriter) { $dictionaryWriter.Dispose() }
            elseif ($dictionaryGzipStream) { $dictionaryGzipStream.Dispose() }
            elseif ($dictionaryFileStream) { $dictionaryFileStream.Dispose() }
        }
        [void]$filesToPublish.Add([PSCustomObject]@{
            StagePath = $dictionaryPath
            TargetPath = Get-VulnContentDictionaryPath -BasePath $BasePath
        })

        $publishedHistoryNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($periodKey in @($periodKeys | Sort-Object -Unique)) {
            if ([string]::IsNullOrWhiteSpace($periodKey)) { continue }
            [void]$publishedHistoryNames.Add([string]::Format($Script:VulnHistoryFileNamePattern, $periodKey))
            [void]$publishedHistoryNames.Add([string]::Format($Script:VulnHistoryRowsFileNamePattern, $periodKey))
            [void]$publishedHistoryNames.Add([string]::Format($Script:VulnHistoryRefsFileNamePattern, $periodKey))
        }
        [void]$publishedHistoryNames.Add($Script:VulnCurrentRefsFileName)
        [void]$publishedHistoryNames.Add($Script:VulnContentDictionaryFileName)
        $removePaths = Get-VulnHistoryRemovePaths -BasePath $BasePath -PublishedHistoryNames $publishedHistoryNames
        if ((Test-Path -LiteralPath (Get-VulnCurrentRefsPath -BasePath $BasePath) -PathType Leaf) -and -not (Test-Path -LiteralPath $currentPath -PathType Leaf)) {
            $removePaths = @($removePaths) + (Get-VulnCurrentRefsPath -BasePath $BasePath)
        }

        Publish-StoreFilesTransactional -BasePath $BasePath -StoreName 'vuln' -Files @($filesToPublish) -RemovePaths @($removePaths)
    }
    finally {
        if (Test-Path -LiteralPath $stageRoot) {
            Remove-Item -LiteralPath $stageRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}


# =============================================================================
# TEMPORARY LEGACY VULNERABILITY MIGRATION HELPERS
# Remove after $Script:LegacyVulnMigrationRemovalDate once legacy VulnExport_* snapshots
# are no longer supported.
# =============================================================================

function Test-VulnStoreRequiresCanonicalRepair {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $true)]
        [object[]]$HistoryDocuments
    )

    $historyFiles = @(Get-ChildItem -Path $BasePath -Filter 'VulnHistory_*.json.gz' -File -ErrorAction SilentlyContinue)
    if (@($historyFiles | Where-Object { $_.BaseName -match '^VulnHistory_\d{4}$' }).Count -gt 0) {
        return $true
    }

    foreach ($historyDocument in @($HistoryDocuments)) {
        $periodKey = Get-VulnHistoryPeriodKeyFromDocument -HistoryDocument $historyDocument
        $rowsPath = Get-VulnHistoryRowsPath -BasePath $BasePath -PeriodKey $periodKey
        if (-not (Test-Path -LiteralPath $rowsPath -PathType Leaf)) {
            return $true
        }
    }

    return $false
}

function Publish-VulnStoreExistingCanonicalState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$LatestSnapshotDate
    )

    $currentPath = Get-VulnCurrentPath -BasePath $BasePath
    $historyDocuments = @(Get-VulnHistoryDocumentList -BasePath $BasePath)
    $requiresCanonicalRepair = Test-VulnStoreRequiresCanonicalRepair -BasePath $BasePath -HistoryDocuments $historyDocuments
    if ($requiresCanonicalRepair) {
        $currentRecords = if (Test-Path -LiteralPath $currentPath -PathType Leaf) {
            @(Read-VulnNdjsonRecordsFromPath -Path $currentPath)
        }
        else {
            @()
        }

        [void](Publish-VulnStoreUnlocked -BasePath $BasePath -Store ([PSCustomObject]@{
            CurrentRecords = $currentRecords
            HistoryDocuments = $historyDocuments
            LatestSnapshotDate = $LatestSnapshotDate
        }))
    }

    $historyPeriodCount = Repair-VulnHistoryLayout -BasePath $BasePath
    $currentRows = if (Test-Path -LiteralPath $currentPath -PathType Leaf) { Test-VulnCurrentFile -Path $currentPath } else { 0 }
    Publish-VulnContentStoreUnlocked -BasePath $BasePath

    return [PSCustomObject]@{
        CurrentRows = $currentRows
        HistoryYears = if ($historyPeriodCount -gt 0) { $historyPeriodCount } else { $historyDocuments.Count }
        LatestSnapshotDate = $LatestSnapshotDate
        MigratedLegacy = $requiresCanonicalRepair
    }
}

function Get-VulnLegacyFilesBySnapshotDate {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo[]]$LegacyFiles,

        [Parameter(Mandatory = $true)]
        [string[]]$SnapshotDates
    )

    $filesByDate = @{}
    foreach ($file in @($LegacyFiles)) {
        $date = Get-VulnSnapshotDateFromName -Name $file.Name
        if ($date -notin $SnapshotDates) { continue }
        if (-not $filesByDate.ContainsKey($date)) {
            $filesByDate[$date] = [System.Collections.Generic.List[object]]::new()
        }
        $filesByDate[$date].Add($file)
    }

    return $filesByDate
}

function Publish-VulnStoreFromLegacySnapshot {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $false)]
        [string[]]$LegacyFilePaths,

        [Parameter(Mandatory = $false)]
        [switch]$RemoveLegacyFiles
    )

    $legacyFiles = @(Get-VulnLegacySnapshotFile -BasePath $BasePath -LegacyFilePaths $LegacyFilePaths)

    if ($legacyFiles.Count -eq 0) {
        throw "No legacy VulnExport snapshot files found in '$BasePath'."
    }

    $publishOutput = @(Invoke-WithStoreLock -BasePath $BasePath -StoreName 'vuln' -ScriptBlock {
        Restore-StoreTransaction -BasePath $BasePath -StoreName 'vuln'

        $storeExists = Test-VulnStoreExistence -BasePath $BasePath
        $partitionCount = $Script:VulnDiskPartitionCount
        $latestKnownSnapshot = if ($storeExists) { Get-VulnStoreLatestSnapshotDate -BasePath $BasePath } else { $null }
        $snapshotDates = @($legacyFiles | ForEach-Object { Get-VulnSnapshotDateFromName -Name $_.Name } | Sort-Object -Unique)

        if (-not [string]::IsNullOrWhiteSpace($latestKnownSnapshot)) {
            $duplicateLatestDates = @($snapshotDates | Where-Object { ([datetime]$_) -eq ([datetime]$latestKnownSnapshot) })
            if ($duplicateLatestDates.Count -gt 0) {
                Write-Verbose "Skipping legacy snapshot dates already represented by the current store latest snapshot date. StoreLatest=$latestKnownSnapshot Incoming=$($duplicateLatestDates -join ', ')"
                $snapshotDates = @($snapshotDates | Where-Object { ([datetime]$_) -ne ([datetime]$latestKnownSnapshot) })
            }

            $backfillDates = @($snapshotDates | Where-Object { ([datetime]$_) -lt ([datetime]$latestKnownSnapshot) })
            if ($backfillDates.Count -gt 0) {
                throw ("Legacy snapshot date(s) {0} are older than the current store latest snapshot date {1}. Incremental import would skip or mis-order those older snapshots. Rebuild the vulnerability store from the full legacy snapshot set before importing backfilled history." -f ($backfillDates -join ', '), $latestKnownSnapshot)
            }
        }

        if ($snapshotDates.Count -eq 0 -and $storeExists) {
            $canonicalState = Publish-VulnStoreExistingCanonicalState -BasePath $BasePath -LatestSnapshotDate $latestKnownSnapshot
            return [PSCustomObject]@{
                DownloadedFiles = $legacyFiles.Count
                CurrentRows = $canonicalState.CurrentRows
                HistoryYears = $canonicalState.HistoryYears
                LatestSnapshotDate = $canonicalState.LatestSnapshotDate
                MigratedLegacy = $canonicalState.MigratedLegacy
                RemovedLegacyFiles = $false
            }
        }

        $filesByDate = Get-VulnLegacyFilesBySnapshotDate -LegacyFiles $legacyFiles -SnapshotDates $snapshotDates

        $stageRoot = Join-Path $BasePath ('.vuln-store-staging-' + [guid]::NewGuid().ToString('N'))
        [void](New-Item -Path $stageRoot -ItemType Directory -Force)

        $historyAppendState = @{}
        try {
            $currentPath = Get-VulnCurrentPath -BasePath $BasePath
            $currentPartitionRoot = Join-Path $stageRoot 'current-partitions'
            [void](New-Item -Path $currentPartitionRoot -ItemType Directory -Force)
            if ($storeExists -and (Test-Path -LiteralPath $currentPath -PathType Leaf)) {
                [void](Split-VulnJsonPartition -InputPaths @($currentPath) -OutputRoot $currentPartitionRoot -Prefix 'current' -PartitionCount $partitionCount)
            }

            Write-Output ("  Canonicalizing {0} new snapshot date(s) across {1} file(s) using {2} disk partition(s)..." -f $snapshotDates.Count, $legacyFiles.Count, $partitionCount)
            foreach ($snapshotDate in $snapshotDates) {
                $closedOn = Get-VulnPreviousDay -Date $snapshotDate
                $snapshotPartitionRoot = Join-Path $stageRoot ('snapshot-' + $snapshotDate)
                [void](New-Item -Path $snapshotPartitionRoot -ItemType Directory -Force)
                $snapshotFilesForDate = @($filesByDate[$snapshotDate] ?? @())
                $snapshotIndex = [array]::IndexOf($snapshotDates, $snapshotDate) + 1
                Write-Output ("  [{0}/{1}] Processing snapshot date {2} from {3} file(s)..." -f $snapshotIndex, $snapshotDates.Count, $snapshotDate, $snapshotFilesForDate.Count)
                if (Get-Command -Name Write-MemoryUsage -ErrorAction SilentlyContinue) {
                    Write-MemoryUsage -Label ("VulnStore " + $snapshotDate + " Start")
                }

                try {
                    [void](Split-VulnJsonPartition `
                        -InputPaths @($snapshotFilesForDate | ForEach-Object { $_.FullName }) `
                        -OutputRoot $snapshotPartitionRoot `
                        -Prefix 'snapshot' `
                        -OnboardedOnly `
                        -PartitionCount $partitionCount)

                    for ($partitionIndex = 0; $partitionIndex -lt $partitionCount; $partitionIndex++) {
                        $currentPartitionPath = Get-VulnPartitionFilePath -Root $currentPartitionRoot -Prefix 'current' -Index $partitionIndex
                        $snapshotPartitionPath = Get-VulnPartitionFilePath -Root $snapshotPartitionRoot -Prefix 'snapshot' -Index $partitionIndex

                        if (-not (Test-Path -LiteralPath $currentPartitionPath -PathType Leaf) -and -not (Test-Path -LiteralPath $snapshotPartitionPath -PathType Leaf)) {
                            continue
                        }

                        $currentMap = Read-VulnPartitionMapFile -Path $currentPartitionPath
                        $snapshotRows = Read-VulnPartitionMapFile -Path $snapshotPartitionPath

                        foreach ($id in @($currentMap.Keys)) {
                            if ($snapshotRows.ContainsKey($id)) { continue }

                            $closedEntry = New-ClosedVulnEntry -Record ($currentMap[$id].Json | ConvertFrom-Json -Depth 20) -Reason 'removed' -ClosedOn $closedOn
                            Add-VulnHistoryEntryToAppendStore -AppendStateByPeriod $historyAppendState -ScratchRoot $stageRoot -SnapshotDate $snapshotDate -ClosedOn $closedOn -Entry $closedEntry
                        }

                        foreach ($id in @($snapshotRows.Keys)) {
                            $incomingVersion = $snapshotRows[$id]
                            $incomingRecord = $incomingVersion.Json | ConvertFrom-Json -Depth 20
                            $existing = $currentMap[$id]
                            $versionStartDate = if ($null -eq $existing -or [string]::IsNullOrWhiteSpace([string]$existing.VersionStartDate)) {
                                $snapshotDate
                            }
                            else {
                                [string]$existing.VersionStartDate
                            }

                            if ($null -ne $existing -and [string]$existing.Signature -ne [string]$incomingVersion.Signature) {
                                $closedEntry = New-ClosedVulnEntry -Record ($existing.Json | ConvertFrom-Json -Depth 20) -Reason 'changed' -ClosedOn $closedOn -ReplacementId $id
                                Add-VulnHistoryEntryToAppendStore -AppendStateByPeriod $historyAppendState -ScratchRoot $stageRoot -SnapshotDate $snapshotDate -ClosedOn $closedOn -Entry $closedEntry
                                $versionStartDate = $snapshotDate
                            }

                            $openRecord = New-OpenVulnRecord -Record $incomingRecord -VersionStartDate $versionStartDate
                            $snapshotRows[$id] = [PSCustomObject]@{
                                Json = $openRecord | ConvertTo-Json -Compress -Depth 20
                                Signature = [string]$incomingVersion.Signature
                                VersionStartDate = $versionStartDate
                            }
                        }

                        [void](Write-VulnPartitionMapFile -Path $currentPartitionPath -RowsById $snapshotRows)
                    }
                }
                finally {
                    if (Get-Command -Name Write-MemoryUsage -ErrorAction SilentlyContinue) {
                        Write-MemoryUsage -Label ("VulnStore " + $snapshotDate + " End")
                    }
                    if (Test-Path -LiteralPath $snapshotPartitionRoot) {
                        Remove-Item -LiteralPath $snapshotPartitionRoot -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }
            }

            Close-VulnHistoryAppendStore -AppendStateByPeriod $historyAppendState

            $stagedCurrentPath = Get-VulnCurrentPath -BasePath $stageRoot
            [void](Write-VulnCurrentFileFromPartition -PartitionRoot $currentPartitionRoot -PartitionPrefix 'current' -OutputPath $stagedCurrentPath -PartitionCount $partitionCount)
            $currentCount = Test-VulnCurrentFile -Path $stagedCurrentPath

            $filesToPublish = [System.Collections.Generic.List[object]]::new()
            $filesToPublish.Add([PSCustomObject]@{
                StagePath = $stagedCurrentPath
                TargetPath = Get-VulnCurrentPath -BasePath $BasePath
            })

            $existingHistoryByPeriod = @{}
            foreach ($historyDocument in Get-VulnHistoryDocumentList -BasePath $BasePath) {
                $existingHistoryByPeriod[(Get-VulnHistoryPeriodKeyFromDocument -HistoryDocument $historyDocument)] = $historyDocument
            }

            $touchedPeriods = @($historyAppendState.Keys | Sort-Object)
            foreach ($periodKey in $touchedPeriods) {
                $appendState = $historyAppendState[$periodKey]
                $existingDocument = if ($existingHistoryByPeriod.ContainsKey($periodKey)) {
                    $existingHistoryByPeriod[$periodKey]
                }
                else {
                    $null
                }
                $existingLatestDate = if ($null -ne $existingDocument) {
                    Get-VulnHistoryDocumentLatestDate -HistoryDocument $existingDocument
                }
                else {
                    $null
                }

                $finalLatestDate = Get-MaxVulnDate `
                    -Primary $existingLatestDate `
                    -Secondary ([string]$appendState.LatestDate)
                $historyStagePath = Get-VulnHistoryPath -BasePath $stageRoot -PeriodKey $periodKey
                Write-VulnHistoryDocumentFromAppendFile `
                    -Path $historyStagePath `
                    -PeriodKey $periodKey `
                    -ExistingDocument $existingDocument `
                    -AppendPath ([string]$appendState.AppendPath) `
                    -LatestDate $finalLatestDate
                [void](Test-VulnHistoryFileLightweight -Path $historyStagePath)
                $historyRowsStagePath = Get-VulnHistoryRowsPath -BasePath $stageRoot -PeriodKey $periodKey
                Write-VulnHistoryRowsFileFromAppendFile `
                    -Path $historyRowsStagePath `
                    -ExistingDocument $existingDocument `
                    -AppendPath ([string]$appendState.AppendPath)

                $filesToPublish.Add([PSCustomObject]@{
                    StagePath = $historyStagePath
                    TargetPath = Get-VulnHistoryPath -BasePath $BasePath -PeriodKey $periodKey
                })
                $filesToPublish.Add([PSCustomObject]@{
                    StagePath = $historyRowsStagePath
                    TargetPath = Get-VulnHistoryRowsPath -BasePath $BasePath -PeriodKey $periodKey
                })
            }

            foreach ($periodKey in @($existingHistoryByPeriod.Keys | Sort-Object)) {
                if ($periodKey -in $touchedPeriods) { continue }

                $historyRowsTargetPath = Get-VulnHistoryRowsPath -BasePath $BasePath -PeriodKey $periodKey
                if (Test-Path -LiteralPath $historyRowsTargetPath -PathType Leaf) { continue }

                $historyRowsStagePath = Get-VulnHistoryRowsPath -BasePath $stageRoot -PeriodKey $periodKey
                Write-VulnHistoryRowsFile -Path $historyRowsStagePath -HistoryDocument $existingHistoryByPeriod[$periodKey]
                $filesToPublish.Add([PSCustomObject]@{
                    StagePath = $historyRowsStagePath
                    TargetPath = $historyRowsTargetPath
                })
            }

            $finalHistoryPeriods = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($periodKey in $existingHistoryByPeriod.Keys) { [void]$finalHistoryPeriods.Add([string]$periodKey) }
            foreach ($periodKey in $touchedPeriods) { [void]$finalHistoryPeriods.Add([string]$periodKey) }

            $publishedHistoryNames = if ($finalHistoryPeriods.Count -gt 0) {
                Get-VulnHistoryPublishedNameSet -PeriodKeys @($finalHistoryPeriods)
            }
            else {
                [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            }
            $historyFilesToRemove = Get-VulnHistoryRemovePaths -BasePath $BasePath -PublishedHistoryNames $publishedHistoryNames
            Publish-StoreFilesTransactional -BasePath $BasePath -StoreName 'vuln' -Files @($filesToPublish) -RemovePaths $historyFilesToRemove
            $historyPeriodCount = Repair-VulnHistoryLayout -BasePath $BasePath
            Publish-VulnContentStoreUnlocked -BasePath $BasePath

            return [PSCustomObject]@{
                DownloadedFiles = $legacyFiles.Count
                CurrentRows = $currentCount
                HistoryYears = if ($historyPeriodCount -gt 0) { $historyPeriodCount } else { $finalHistoryPeriods.Count }
                LatestSnapshotDate = if ($snapshotDates.Count -gt 0) { $snapshotDates[-1] } else { $latestKnownSnapshot }
                MigratedLegacy = $true
                RemovedLegacyFiles = $false
            }
        }
        finally {
            Close-VulnHistoryAppendStore -AppendStateByPeriod $historyAppendState
            if (Test-Path -LiteralPath $stageRoot) {
                Remove-Item -LiteralPath $stageRoot -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    })

    $publishResult = $null
    foreach ($item in $publishOutput) {
        if ($null -ne $item -and $item.PSObject.Properties.Match('MigratedLegacy').Count -gt 0) {
            $publishResult = $item
            continue
        }

        if ($null -ne $item) {
            Write-Host ([string]$item)
        }
    }

    if ($null -eq $publishResult) {
        throw 'Publish-VulnStoreFromLegacySnapshot did not return a publish result.'
    }

    if ($RemoveLegacyFiles) {
        foreach ($legacyFile in @(Get-VulnLegacySnapshotFile -BasePath $BasePath)) {
            Remove-Item -Path $legacyFile.FullName -Force
        }
    }

    return [PSCustomObject]@{
        DownloadedFiles = $publishResult.DownloadedFiles
        CurrentRows = $publishResult.CurrentRows
        HistoryYears = $publishResult.HistoryYears
        LatestSnapshotDate = $publishResult.LatestSnapshotDate
        MigratedLegacy = $publishResult.MigratedLegacy
        RemovedLegacyFiles = ($RemoveLegacyFiles -eq $true)
    }
}

function Read-VulnStoreRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    Invoke-WithStoreLock -BasePath $BasePath -StoreName 'vuln' -ScriptBlock {
        Restore-StoreTransaction -BasePath $BasePath -StoreName 'vuln'

        if (-not (Test-VulnContentStoreExistence -BasePath $BasePath)) {
            try {
                Publish-VulnContentStoreUnlocked -BasePath $BasePath
            }
            catch {
                Write-Verbose "Vulnerability content sidecar rebuild failed; falling back to raw row files. $_"
            }
        }

        if (Test-VulnContentStoreExistence -BasePath $BasePath) {
            foreach ($record in Read-VulnContentStoreRow -BasePath $BasePath) {
                Write-Output $record
            }
            return
        }

        $currentPath = Get-VulnCurrentPath -BasePath $BasePath
        if (Test-Path -Path $currentPath) {
            foreach ($record in Read-VulnNdjsonRecordsFromPath -Path $currentPath) {
                Write-Output $record
            }
        }

        $historyFiles = @(Get-ChildItem -Path $BasePath -Filter 'VulnHistory_*.json.gz' -File | Sort-Object Name)
        foreach ($file in $historyFiles) {
            $periodMatch = [regex]::Match($file.Name, '^VulnHistory_(?<period>\d{4}Q[1-4]|\d{4})\.json\.gz$')
            $rowsPath = if ($periodMatch.Success) {
                Get-VulnHistoryRowsPath -BasePath $BasePath -PeriodKey $periodMatch.Groups['period'].Value
            }
            else {
                $null
            }
            $rowsReadPath = if (-not [string]::IsNullOrWhiteSpace($rowsPath) -and (Test-Path -LiteralPath $rowsPath -PathType Leaf)) {
                $rowsPath
            }
            elseif (-not [string]::IsNullOrWhiteSpace($rowsPath)) {
                $legacyRowsPath = $rowsPath -replace '\.gz$', ''
                if (Test-Path -LiteralPath $legacyRowsPath -PathType Leaf) { $legacyRowsPath } else { $null }
            }
            else {
                $null
            }

            if (-not [string]::IsNullOrWhiteSpace($rowsReadPath)) {
                foreach ($record in Read-VulnNdjsonRecordsFromPath -Path $rowsReadPath) {
                    Write-Output $record
                }
                continue
            }

            foreach ($record in Read-VulnHistoryRowsFromPath -Path $file.FullName) {
                Write-Output $record
            }
        }
    } | Write-Output
}

function Write-VulnCompatibilitySnapshotFromStore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Store,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $fileStream = [System.IO.File]::Create($OutputPath)
    $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Compress)
    $writer = [System.IO.StreamWriter]::new($gzipStream, [System.Text.UTF8Encoding]::new($false))
    try {
        foreach ($record in $Store.CurrentRecords) {
            if ($null -eq $record) { continue }
            $writer.WriteLine(($record | ConvertTo-Json -Compress -Depth 20))
        }

        foreach ($historyDocument in $Store.HistoryDocuments) {
            foreach ($snapshot in $historyDocument.snapshots) {
                foreach ($entry in $snapshot.closed) {
                    $row = Get-VulnPropertyValue -InputObject $entry -Name 'row'
                    if ($null -eq $row) { continue }
                    $writer.WriteLine(($row | ConvertTo-Json -Compress -Depth 20))
                }
            }
        }
    }
    finally {
        $writer.Dispose()
    }
}

function Write-VulnCompatibilitySnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $fileStream = [System.IO.File]::Create($OutputPath)
    $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Compress)
    $writer = [System.IO.StreamWriter]::new($gzipStream, [System.Text.UTF8Encoding]::new($false))
    try {
        foreach ($record in Read-VulnStoreRow -BasePath $BasePath) {
            if ($null -eq $record) { continue }
            $writer.WriteLine(($record | ConvertTo-Json -Compress -Depth 20))
        }
    }
    finally {
        $writer.Dispose()
    }
}

function Test-VulnCurrentFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $idSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $rowCount = 0
    foreach ($row in Read-VulnNdjsonRecordsFromPath -Path $Path) {
        $id = [string](Get-VulnPropertyValue -InputObject $row -Name 'Id')
        if ([string]::IsNullOrWhiteSpace($id)) {
            throw "Current vulnerability store contains a row without Id."
        }
        if (-not $idSet.Add($id)) {
            throw "Current vulnerability store contains duplicate Id '$id'."
        }
        $rowCount++
    }

    return $rowCount
}

function Test-VulnHistoryFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $document = Read-VulnHistoryDocument -Path $Path
    $hasYear = $null -ne $document.PSObject.Properties['year']
    $hasPeriod = $null -ne $document.PSObject.Properties['period']
    $hasQuarter = $null -ne $document.PSObject.Properties['quarter']
    if ((-not $hasYear) -or (($hasPeriod -or $hasQuarter) -and -not ($hasPeriod -and $hasQuarter))) {
        throw "History file '$Path' is missing required partition metadata."
    }
    if ($null -eq $document.PSObject.Properties['snapshots']) {
        throw "History file '$Path' is missing 'snapshots'."
    }

    $snapshotDates = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($snapshot in @($document.snapshots)) {
        if ($null -eq $snapshot) { continue }
        $date = [string](Get-VulnPropertyValue -InputObject $snapshot -Name 'date')
        if ([string]::IsNullOrWhiteSpace($date)) {
            throw "History file '$Path' contains a snapshot without date."
        }
        if (-not $snapshotDates.Add($date)) {
            throw "History file '$Path' contains duplicate snapshot date '$date'."
        }
        foreach ($entry in @($snapshot.closed)) {
            if ($null -eq $entry) { continue }
            $reason = [string](Get-VulnPropertyValue -InputObject $entry -Name 'reason')
            if ($reason -notin @('removed', 'changed')) {
                throw "History file '$Path' contains invalid close reason '$reason'."
            }
            $row = Get-VulnPropertyValue -InputObject $entry -Name 'row'
            if ($null -eq $row) {
                throw "History file '$Path' contains a closed entry without row payload."
            }
            $id = [string](Get-VulnPropertyValue -InputObject $row -Name 'Id')
            if ([string]::IsNullOrWhiteSpace($id)) {
                throw "History file '$Path' contains a closed row without Id."
            }
        }
    }

    $storedLatestDate = [string](Get-VulnPropertyValue -InputObject $document -Name 'latestDate')
    if (-not [string]::IsNullOrWhiteSpace($storedLatestDate) -and $snapshotDates.Count -gt 0) {
        $maxSnapshotDate = @($snapshotDates | Sort-Object)[-1]
        if ($storedLatestDate -ne $maxSnapshotDate) {
            throw "History file '$Path' latestDate '$storedLatestDate' does not match max snapshot date '$maxSnapshotDate'."
        }
    }

    return @($document.snapshots).Count
}

function Test-VulnHistoryFileLightweight {
    [CmdletBinding()]
    [OutputType([int])]
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
                $prefixBuilder = [System.Text.StringBuilder]::new()
                $buffer = New-Object char[] 8192
                $totalChars = 0

                while (($charsRead = $reader.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    if ($prefixBuilder.Length -lt 4096) {
                        $charsToKeep = [Math]::Min(4096 - $prefixBuilder.Length, $charsRead)
                        [void]$prefixBuilder.Append($buffer, 0, $charsToKeep)
                    }
                    $totalChars += $charsRead
                }

                if ($totalChars -eq 0) {
                    throw "History file '$Path' is empty."
                }

                $prefix = $prefixBuilder.ToString()
                if ($prefix -notmatch '^\s*\{') {
                    throw "History file '$Path' does not begin with a JSON object."
                }
                if ($prefix -notmatch '"year"\s*:') {
                    throw "History file '$Path' is missing 'year'."
                }
                if ($prefix -notmatch '"latestDate"\s*:') {
                    throw "History file '$Path' is missing 'latestDate'."
                }
                if ($prefix -notmatch '"snapshots"\s*:') {
                    throw "History file '$Path' is missing 'snapshots'."
                }
                $hasPeriod = $prefix -match '"period"\s*:'
                $hasQuarter = $prefix -match '"quarter"\s*:'
                if ($hasPeriod -xor $hasQuarter) {
                    throw "History file '$Path' has incomplete quarter partition metadata."
                }

                return $totalChars
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

function Get-VulnHistoryDocumentList {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    $documents = [System.Collections.Generic.List[object]]::new()
    foreach ($file in Get-ChildItem -Path $BasePath -Filter 'VulnHistory_*.json.gz' -File -ErrorAction SilentlyContinue | Sort-Object Name) {
        foreach ($document in Convert-VulnHistoryDocumentToQuarterlyDocuments -HistoryDocument (Read-VulnHistoryDocument -Path $file.FullName)) {
            $documents.Add($document)
        }
    }

    return @($documents)
}

function Get-VulnStoreLatestSnapshotDate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    $maxDate = $null

    $currentPath = Get-VulnCurrentPath -BasePath $BasePath
    if (Test-Path -Path $currentPath) {
        foreach ($record in Read-VulnNdjsonRecordsFromPath -Path $currentPath) {
            $lastSeen = Convert-VulnToYmdDate -DateValue (Get-VulnPropertyValue -InputObject $record -Name 'LastSeenTimestamp')
            if (-not [string]::IsNullOrWhiteSpace($lastSeen)) {
                $maxDate = Get-MaxVulnDate -Primary $maxDate -Secondary $lastSeen
            }
        }
    }

    foreach ($file in Get-ChildItem -Path $BasePath -Filter 'VulnHistory_*.json.gz' -File -ErrorAction SilentlyContinue | Sort-Object Name) {
        $docLatest = Get-VulnHistoryFileLatestDate -Path $file.FullName
        if (-not [string]::IsNullOrWhiteSpace($docLatest)) {
            $maxDate = Get-MaxVulnDate -Primary $maxDate -Secondary $docLatest
        }
    }

    return $maxDate
}

function Add-VulnHistoryEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$HistoryByPeriod,

        [Parameter(Mandatory = $true)]
        [string]$SnapshotDate,

        [Parameter(Mandatory = $true)]
        [string]$ClosedOn,

        [Parameter(Mandatory = $true)]
        $Entry,

        [hashtable]$SnapshotMaps = $null
    )

    $periodKey = Get-VulnHistoryPeriodKeyFromDate -Date $ClosedOn
    if (-not $HistoryByPeriod.ContainsKey($periodKey)) {
        $HistoryByPeriod[$periodKey] = Get-VulnHistorySeed -PeriodKey $periodKey
    }

    if ($null -ne $SnapshotMaps) {
        if (-not $SnapshotMaps.ContainsKey($periodKey)) {
            $SnapshotMaps[$periodKey] = Get-VulnHistorySnapshotMap -HistoryDocument $HistoryByPeriod[$periodKey]
        }
        $snapshotMap = $SnapshotMaps[$periodKey]
        if (-not $snapshotMap.ContainsKey($SnapshotDate)) {
            $newSnapshot = [PSCustomObject]@{ date = $SnapshotDate; closed = @() }
            $HistoryByPeriod[$periodKey].snapshots += $newSnapshot
            $snapshotMap[$SnapshotDate] = $newSnapshot
        }
    } else {
        $snapshotMap = Get-VulnHistorySnapshotMap -HistoryDocument $HistoryByPeriod[$periodKey]
        if (-not $snapshotMap.ContainsKey($SnapshotDate)) {
            $HistoryByPeriod[$periodKey].snapshots += [PSCustomObject]@{ date = $SnapshotDate; closed = @() }
            $snapshotMap = Get-VulnHistorySnapshotMap -HistoryDocument $HistoryByPeriod[$periodKey]
        }
    }

    $snapshotMap[$SnapshotDate].closed += $Entry

    $currentLatest = [string](Get-VulnPropertyValue -InputObject $HistoryByPeriod[$periodKey] -Name 'latestDate')
    $newLatest = Get-MaxVulnDate -Primary $currentLatest -Secondary $SnapshotDate
    if ($HistoryByPeriod[$periodKey] -is [System.Collections.IDictionary]) {
        $HistoryByPeriod[$periodKey]['latestDate'] = $newLatest
    } else {
        $HistoryByPeriod[$periodKey] | Add-Member -NotePropertyName 'latestDate' -NotePropertyValue $newLatest -Force
    }
}

function Update-VulnStoreFromLegacySnapshot {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $false)]
        [string[]]$LegacyFilePaths
    )

    $legacyFiles = @(Get-VulnLegacySnapshotFile -BasePath $BasePath -LegacyFilePaths $LegacyFilePaths)

    if ($legacyFiles.Count -eq 0) {
        throw "No legacy VulnExport snapshot files found in '$BasePath'."
    }

    if (-not (Test-VulnStoreExistence -BasePath $BasePath)) {
        return (Convert-LegacyVulnSnapshotsToStore -BasePath $BasePath)
    }

    $currentMap = @{}
    $currentPath = Get-VulnCurrentPath -BasePath $BasePath
    if (Test-Path -Path $currentPath) {
        foreach ($record in Read-VulnNdjsonRecordsFromPath -Path $currentPath) {
            $id = [string](Get-VulnPropertyValue -InputObject $record -Name 'Id')
            if ([string]::IsNullOrWhiteSpace($id)) { continue }

            $versionStartDate = Convert-VulnToYmdDate -DateValue (Get-VulnPropertyValue -InputObject $record -Name 'FirstSeenTimestamp')
            $currentMap[$id] = [PSCustomObject]@{
                Record = $record
                Signature = Get-VulnCanonicalRowSignature -Row $record
                VersionStartDate = $versionStartDate
            }
        }
    }

    $historyByPeriod = @{}
    foreach ($document in Get-VulnHistoryDocumentList -BasePath $BasePath) {
        $historyByPeriod[(Get-VulnHistoryPeriodKeyFromDocument -HistoryDocument $document)] = $document
    }
    $snapshotMaps = @{}

    $latestKnownSnapshot = Get-VulnStoreLatestSnapshotDate -BasePath $BasePath
    $snapshotDates = @($legacyFiles | ForEach-Object { Get-VulnSnapshotDateFromName -Name $_.Name } | Sort-Object -Unique)

    if (-not [string]::IsNullOrWhiteSpace($latestKnownSnapshot)) {
        $duplicateLatestDates = @($snapshotDates | Where-Object { ([datetime]$_) -eq ([datetime]$latestKnownSnapshot) })
        if ($duplicateLatestDates.Count -gt 0) {
            Write-Verbose "Skipping legacy snapshot dates already represented by the current store latest snapshot date. StoreLatest=$latestKnownSnapshot Incoming=$($duplicateLatestDates -join ', ')"
            $snapshotDates = @($snapshotDates | Where-Object { ([datetime]$_) -ne ([datetime]$latestKnownSnapshot) })
        }

        $backfillDates = @($snapshotDates | Where-Object { ([datetime]$_) -lt ([datetime]$latestKnownSnapshot) })
        if ($backfillDates.Count -gt 0) {
            throw ("Legacy snapshot date(s) {0} are older than the current store latest snapshot date {1}. Incremental import would skip or mis-order those older snapshots. Rebuild the vulnerability store from the full legacy snapshot set before importing backfilled history." -f ($backfillDates -join ', '), $latestKnownSnapshot)
        }
    }

    if ($snapshotDates.Count -eq 0) {
        return [PSCustomObject]@{
            CurrentRecords = @($currentMap.Values | Sort-Object { $_.Record.Id } | ForEach-Object { $_.Record })
            HistoryDocuments = @($historyByPeriod.Values | Sort-Object period)
            SnapshotCount = 0
            LatestSnapshotDate = $latestKnownSnapshot
        }
    }

    $filesByDate = @{}
    foreach ($file in $legacyFiles) {
        $date = Get-VulnSnapshotDateFromName -Name $file.Name
        if (-not $filesByDate.ContainsKey($date)) { $filesByDate[$date] = [System.Collections.Generic.List[object]]::new() }
        $filesByDate[$date].Add($file)
    }

    foreach ($snapshotDate in $snapshotDates) {
        $snapshotRows = @{}
        foreach ($file in ($filesByDate[$snapshotDate] ?? @())) {
            foreach ($record in Read-VulnNdjsonRecordsFromPath -Path $file.FullName) {
                $id = [string](Get-VulnPropertyValue -InputObject $record -Name 'Id')
                if ([string]::IsNullOrWhiteSpace($id)) { continue }
                if ((Get-VulnPropertyValue -InputObject $record -Name 'IsOnboarded') -ne $true) { continue }
                $snapshotRows[$id] = $record
            }
        }

        foreach ($id in @($currentMap.Keys)) {
            if ($snapshotRows.ContainsKey($id)) { continue }

            $closedOn = Get-VulnPreviousDay -Date $snapshotDate
            $closedEntry = New-ClosedVulnEntry -Record $currentMap[$id].Record -Reason 'removed' -ClosedOn $closedOn
            Add-VulnHistoryEntry -HistoryByPeriod $historyByPeriod -SnapshotDate $snapshotDate -ClosedOn $closedOn -Entry $closedEntry -SnapshotMaps $snapshotMaps
            $currentMap.Remove($id)
        }

        foreach ($id in $snapshotRows.Keys) {
            $record = $snapshotRows[$id]
            $signature = Get-VulnCanonicalRowSignature -Row $record

            if (-not $currentMap.ContainsKey($id)) {
                $currentMap[$id] = [PSCustomObject]@{
                    Record = New-OpenVulnRecord -Record $record -VersionStartDate $snapshotDate
                    Signature = $signature
                    VersionStartDate = $snapshotDate
                }
                continue
            }

            $currentVersion = $currentMap[$id]
            if ($currentVersion.Signature -eq $signature) {
                $versionStartDate = if ([string]::IsNullOrWhiteSpace($currentVersion.VersionStartDate)) { $snapshotDate } else { $currentVersion.VersionStartDate }
                $currentMap[$id] = [PSCustomObject]@{
                    Record = New-OpenVulnRecord -Record $record -VersionStartDate $versionStartDate
                    Signature = $signature
                    VersionStartDate = $versionStartDate
                }
                continue
            }

            $closedOn = Get-VulnPreviousDay -Date $snapshotDate
            $closedEntry = New-ClosedVulnEntry -Record $currentVersion.Record -Reason 'changed' -ClosedOn $closedOn -ReplacementId $id
            Add-VulnHistoryEntry -HistoryByPeriod $historyByPeriod -SnapshotDate $snapshotDate -ClosedOn $closedOn -Entry $closedEntry -SnapshotMaps $snapshotMaps

            $currentMap[$id] = [PSCustomObject]@{
                Record = New-OpenVulnRecord -Record $record -VersionStartDate $snapshotDate
                Signature = $signature
                VersionStartDate = $snapshotDate
            }
        }
    }

    return [PSCustomObject]@{
        CurrentRecords = @($currentMap.Values | Sort-Object { $_.Record.Id } | ForEach-Object { $_.Record })
        HistoryDocuments = @($historyByPeriod.Values | Sort-Object period)
        SnapshotCount = $snapshotDates.Count
        LatestSnapshotDate = $snapshotDates[-1]
    }
}

function Convert-LegacyVulnSnapshotsToStore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    $legacyFiles = @(Get-VulnLegacySnapshotFile -BasePath $BasePath)
    if ($legacyFiles.Count -eq 0) {
        throw "No legacy VulnExport snapshot files found in '$BasePath'."
    }

    $openVersions = @{}
    $historyByPeriod = @{}
    $snapshotMaps = @{}
    $allSnapshotDates = @($legacyFiles | ForEach-Object { Get-VulnSnapshotDateFromName -Name $_.Name } | Sort-Object -Unique)
    $lastSnapshotDate = $allSnapshotDates[-1]

    $filesByDate = @{}
    foreach ($file in $legacyFiles) {
        $date = Get-VulnSnapshotDateFromName -Name $file.Name
        if (-not $filesByDate.ContainsKey($date)) { $filesByDate[$date] = [System.Collections.Generic.List[object]]::new() }
        $filesByDate[$date].Add($file)
    }

    foreach ($snapshotDate in $allSnapshotDates) {
        $snapshotRows = @{}
        foreach ($file in ($filesByDate[$snapshotDate] ?? @())) {
            foreach ($record in Read-VulnNdjsonRecordsFromPath -Path $file.FullName) {
                $id = [string](Get-VulnPropertyValue -InputObject $record -Name 'Id')
                if ([string]::IsNullOrWhiteSpace($id)) { continue }
                if ((Get-VulnPropertyValue -InputObject $record -Name 'IsOnboarded') -ne $true) { continue }
                $snapshotRows[$id] = $record
            }
        }

        foreach ($id in @($openVersions.Keys)) {
            if (-not $snapshotRows.ContainsKey($id)) {
                $closedOn = Get-VulnPreviousDay -Date $snapshotDate
                $closedEntry = New-ClosedVulnEntry -Record $openVersions[$id].Record -Reason 'removed' -ClosedOn $closedOn
                Add-VulnHistoryEntry -HistoryByPeriod $historyByPeriod -SnapshotDate $snapshotDate -ClosedOn $closedOn -Entry $closedEntry -SnapshotMaps $snapshotMaps
                $openVersions.Remove($id)
            }
        }

        foreach ($id in $snapshotRows.Keys) {
            $record = $snapshotRows[$id]
            $signature = Get-VulnCanonicalRowSignature -Row $record

            if (-not $openVersions.ContainsKey($id)) {
                $openVersions[$id] = [PSCustomObject]@{
                    Record = New-OpenVulnRecord -Record $record -VersionStartDate $snapshotDate
                    Signature = $signature
                    VersionStartDate = $snapshotDate
                }
                continue
            }

            $openVersion = $openVersions[$id]
            if ($openVersion.Signature -eq $signature) {
                $updatedRecord = New-OpenVulnRecord -Record $record -VersionStartDate $openVersion.VersionStartDate
                $openVersions[$id] = [PSCustomObject]@{
                    Record = $updatedRecord
                    Signature = $signature
                    VersionStartDate = $openVersion.VersionStartDate
                }
                continue
            }

            $closedOn = Get-VulnPreviousDay -Date $snapshotDate
            $closedEntry = New-ClosedVulnEntry -Record $openVersion.Record -Reason 'changed' -ClosedOn $closedOn -ReplacementId $id
            Add-VulnHistoryEntry -HistoryByPeriod $historyByPeriod -SnapshotDate $snapshotDate -ClosedOn $closedOn -Entry $closedEntry -SnapshotMaps $snapshotMaps

            $openVersions[$id] = [PSCustomObject]@{
                Record = New-OpenVulnRecord -Record $record -VersionStartDate $snapshotDate
                Signature = $signature
                VersionStartDate = $snapshotDate
            }
        }
    }

    $currentRecords = @($openVersions.Values | Sort-Object { $_.Record.Id } | ForEach-Object { $_.Record })
    return [PSCustomObject]@{
        CurrentRecords = $currentRecords
        HistoryDocuments = @($historyByPeriod.Values | Sort-Object period)
        SnapshotCount = $allSnapshotDates.Count
        LatestSnapshotDate = $lastSnapshotDate
    }
}


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

function Get-JsonFileMode {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $fileStream = [System.IO.File]::OpenRead($Path)
    try {
        $contentStream = if ($Path.EndsWith('.gz', [System.StringComparison]::OrdinalIgnoreCase)) {
            [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Decompress)
        } else { $fileStream }
        try {
            $reader = [System.IO.StreamReader]::new($contentStream, [System.Text.Encoding]::UTF8, $true)
            try {
                while (-not $reader.EndOfStream) {
                    $charValue = $reader.Read()
                    if ($charValue -lt 0) { break }
                    $char = [char]$charValue
                    if (-not [char]::IsWhiteSpace($char)) {
                        if ($char -eq '[') { return 'Array' }
                        return 'Ndjson'
                    }
                }
                return 'Empty'
            }
            finally { $reader.Dispose() }
        }
        finally { if ($contentStream -ne $fileStream) { $contentStream.Dispose() } }
    }
    finally { $fileStream.Dispose() }
}

function Read-MachineRecordsFromFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $fileMode = Get-JsonFileMode -Path $Path
    if ($fileMode -eq 'Empty') {
        return
    }

    if ($fileMode -eq 'Array') {
        $rawContent = Read-TextFileContent -Path $Path
        $machineList = $rawContent | ConvertFrom-Json
        $rawContent = $null
        if ($null -eq $machineList) { return }
        if ($machineList -isnot [System.Array]) { $machineList = @($machineList) }

        foreach ($machine in $machineList) {
            if ($null -eq $machine) { continue }
            if ($machine.PSObject.Properties['removed']?.Value -eq $true) {
                Write-Output ([PSCustomObject]@{
                    id = $machine.PSObject.Properties['id']?.Value
                    observedOn = $machine.PSObject.Properties['observedOn']?.Value
                    removed = $true
                    stateHash = $machine.PSObject.Properties['stateHash']?.Value
                })
                continue
            }
            $record = ConvertTo-CompactMachineRecord -Machine $machine
            $stateHash = $machine.PSObject.Properties['stateHash']?.Value
            $observedOn = $machine.PSObject.Properties['observedOn']?.Value
            if ($stateHash) { Add-Member -InputObject $record -NotePropertyName stateHash -NotePropertyValue $stateHash }
            if ($observedOn) { Add-Member -InputObject $record -NotePropertyName observedOn -NotePropertyValue $observedOn }
            Write-Output $record
        }

        return
    }

    $fileStream = [System.IO.File]::OpenRead($Path)
    try {
        $contentStream = if ($Path.EndsWith('.gz', [System.StringComparison]::OrdinalIgnoreCase)) {
            [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Decompress)
        } else { $fileStream }
        try {
            $reader = [System.IO.StreamReader]::new($contentStream, [System.Text.UTF8Encoding]::new($false))
            try {
                while (-not $reader.EndOfStream) {
                    $line = $reader.ReadLine()
                    if ([string]::IsNullOrWhiteSpace($line)) { continue }
                    try {
                        $machine = $line | ConvertFrom-Json
                    }
                    catch {
                        Write-Warning "Failed to parse machine line in $(Split-Path -Leaf $Path): $_"
                        continue
                    }

                    if ($null -eq $machine) { continue }
                    if ($machine.PSObject.Properties['removed']?.Value -eq $true) {
                        Write-Output ([PSCustomObject]@{
                            id = $machine.PSObject.Properties['id']?.Value
                            observedOn = $machine.PSObject.Properties['observedOn']?.Value
                            removed = $true
                            stateHash = $machine.PSObject.Properties['stateHash']?.Value
                        })
                        continue
                    }
                    $record = ConvertTo-CompactMachineRecord -Machine $machine
                    $stateHash = $machine.PSObject.Properties['stateHash']?.Value
                    $observedOn = $machine.PSObject.Properties['observedOn']?.Value
                    if ($stateHash) { Add-Member -InputObject $record -NotePropertyName stateHash -NotePropertyValue $stateHash }
                    if ($observedOn) { Add-Member -InputObject $record -NotePropertyName observedOn -NotePropertyValue $observedOn }
                    Write-Output $record
                }
            }
            finally { $reader.Dispose() }
        }
        finally { if ($contentStream -ne $fileStream) { $contentStream.Dispose() } }
    }
    finally { $fileStream.Dispose() }
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
    try {
        if ($Path.EndsWith('.gz', [System.StringComparison]::OrdinalIgnoreCase)) {
            $fileStream = [System.IO.File]::Create($Path)
            $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Compress)
            $writer = [System.IO.StreamWriter]::new($gzipStream, [System.Text.UTF8Encoding]::new($false))
        }
        else {
            $writer = [System.IO.StreamWriter]::new($Path, $false, [System.Text.UTF8Encoding]::new($false))
        }

        foreach ($record in $Records) {
            if ($null -eq $record) { continue }
            $writer.WriteLine(($record | ConvertTo-Json -Compress -Depth 6))
        }
    }
    finally {
        if ($writer) { $writer.Dispose() }
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

    foreach ($sourcePath in $historySourcePaths) {
        foreach ($record in Read-MachineRecordsFromFile -Path $sourcePath) {
            Add-MachineHistoryRecordToPeriodMap -HistoryRecordsByPeriod $historyRecordsByPeriod -RecordKeys $historyRecordKeys -Record $record
        }
    }

    if ($null -ne $currentReadPath) {
        foreach ($record in Read-MachineRecordsFromFile -Path $currentReadPath) {
            if (-not $record.id) { continue }
            if ($record.PSObject.Properties['removed']?.Value -eq $true) {
                $currentRecords.Remove($record.id)
                continue
            }
            if (-not $record.PSObject.Properties['stateHash']) {
                Add-Member -InputObject $record -NotePropertyName stateHash -NotePropertyValue (Get-MachineStateHash -Machine $record)
            }
            if (-not $record.PSObject.Properties['observedOn']) {
                Add-Member -InputObject $record -NotePropertyName observedOn -NotePropertyValue (Get-Date -Format 'yyyy-MM-dd')
            }
            $currentRecords[$record.id] = $record
        }
    } elseif ($historySourcePaths.Count -gt 0) {
        foreach ($sourcePath in $historySourcePaths) {
            foreach ($record in Read-MachineRecordsFromFile -Path $sourcePath) {
                if (-not $record.id) { continue }
                if ($record.PSObject.Properties['removed']?.Value -eq $true) {
                    $currentRecords.Remove($record.id)
                    continue
                }
                if (-not $record.PSObject.Properties['stateHash']) {
                    Add-Member -InputObject $record -NotePropertyName stateHash -NotePropertyValue (Get-MachineStateHash -Machine $record)
                }
                if (-not $record.PSObject.Properties['observedOn']) {
                    Add-Member -InputObject $record -NotePropertyName observedOn -NotePropertyValue (Get-Date -Format 'yyyy-MM-dd')
                }
                $currentRecords[$record.id] = $record
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
            if (-not $record.PSObject.Properties['stateHash']) {
                Add-Member -InputObject $record -NotePropertyName stateHash -NotePropertyValue (Get-MachineStateHash -Machine $record)
            }
            if (-not $record.PSObject.Properties['observedOn']) {
                Add-Member -InputObject $record -NotePropertyName observedOn -NotePropertyValue (Get-Date -Format 'yyyy-MM-dd')
            }
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

function Read-AdvancedHuntingRecordsFromFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $fileMode = Get-JsonFileMode -Path $Path
    if ($fileMode -eq 'Empty') {
        return
    }

    if ($fileMode -eq 'Array') {
        $rawContent = Read-TextFileContent -Path $Path
        $records = $rawContent | ConvertFrom-Json
        $rawContent = $null
        if ($null -eq $records) { return }
        if ($records -isnot [System.Array]) { $records = @($records) }

        foreach ($record in $records) {
            if ($null -ne $record) {
                Write-Output $record
            }
        }

        return
    }

    $fileStream = [System.IO.File]::OpenRead($Path)
    try {
        $contentStream = if ($Path.EndsWith('.gz', [System.StringComparison]::OrdinalIgnoreCase)) {
            [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Decompress)
        } else { $fileStream }
        try {
            $reader = [System.IO.StreamReader]::new($contentStream, [System.Text.UTF8Encoding]::new($false))
            try {
                while (-not $reader.EndOfStream) {
                    $line = $reader.ReadLine()
                    if ([string]::IsNullOrWhiteSpace($line)) { continue }
                    try {
                        $record = $line | ConvertFrom-Json
                        if ($null -ne $record) { Write-Output $record }
                    }
                    catch {
                        Write-Warning "Failed to parse Advanced Hunting line in $(Split-Path -Leaf $Path): $_"
                    }
                }
            }
            finally { $reader.Dispose() }
        }
        finally { if ($contentStream -ne $fileStream) { $contentStream.Dispose() } }
    }
    finally { $fileStream.Dispose() }
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
            $cveId = $record.PSObject.Properties['CveId']?.Value
            if ($cveId) {
                $currentRecords[$cveId] = $record
            }
        }
    }
    elseif (Test-Path -Path $legacyCurrentPath) {
        foreach ($record in Read-AdvancedHuntingRecordsFromFile -Path $legacyCurrentPath) {
            $cveId = $record.PSObject.Properties['CveId']?.Value
            if ($cveId) {
                $currentRecords[$cveId] = $record
            }
        }
        $migratedLegacy = $true
    }

    if ($legacyFiles.Count -gt 0) {
        foreach ($file in $legacyFiles) {
            $fallbackDate = [regex]::Match($file.Name, '\d{4}-\d{2}-\d{2}').Value
            foreach ($record in Read-AdvancedHuntingRecordsFromFile -Path $file.FullName) {
                $cveId = $record.PSObject.Properties['CveId']?.Value
                if (-not $cveId) { continue }

                $incomingKey = Get-AdvancedHuntingLastModifiedKey -LastModifiedTime $record.PSObject.Properties['LastModifiedTime']?.Value -FallbackDate $fallbackDate
                $existing = $currentRecords[$cveId]

                if ($null -eq $existing) {
                    $currentRecords[$cveId] = $record
                    $migratedLegacy = $true
                    continue
                }

                $existingKey = Get-AdvancedHuntingLastModifiedKey -LastModifiedTime $existing.PSObject.Properties['LastModifiedTime']?.Value -FallbackDate ''
                if ([string]::CompareOrdinal($incomingKey, $existingKey) -gt 0) {
                    $currentRecords[$cveId] = $record
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


# Shared MDE export helpers used by local export, generator refresh, and the Azure runbook.

function Get-MdeHeaderCollection {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccessToken
    )

    return @{
        'Content-Type'  = 'application/json'
        'Accept'        = 'application/json'
        'Authorization' = "Bearer $AccessToken"
    }
}

function Invoke-MdeBulkVulnerabilitySnapshotDownload {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [string]$ExportUrl
    )

    $response = Invoke-RestMethod -Uri $ExportUrl -Headers $Headers -Method Get -ErrorAction Stop
    $exportFiles = @($response.exportFiles)
    if ($exportFiles.Count -eq 0) {
        throw 'Bulk vulnerability export returned no files.'
    }

    $downloadedFiles = [System.Collections.Generic.List[string]]::new()
    foreach ($fileUrl in $exportFiles) {
        if ($fileUrl -match '/collection/([^/?]+)/.*%3DgroupId%3D([^&%? ]+)') {
            $date = $Matches[1]
            $groupId = [System.Uri]::UnescapeDataString($Matches[2])
        }
        elseif ($fileUrl -match '/flat-va/([^/?]+)/[^/?]+/json/_RbacGroupId(?:%3D|=)([^/?&]+)') {
            $date = $Matches[1]
            $groupId = [System.Uri]::UnescapeDataString($Matches[2])
        }
        else {
            throw "Unexpected export URL format. Cannot extract date and groupId from: $fileUrl"
        }

        $outputFile = Join-Path $OutputPath "VulnExport_${groupId}_${date}.json.gz"
        Invoke-WebRequest -Uri $fileUrl -OutFile $outputFile
        $downloadedFiles.Add($outputFile)
    }

    return [PSCustomObject]@{
        ExportFileCount = $exportFiles.Count
        DownloadedFiles = @($downloadedFiles)
    }
}

function Invoke-MdeAdvancedHuntingStoreRefresh {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [string]$QueryUrl
    )

    $query = @"
DeviceTvmSoftwareVulnerabilities
| join kind=leftouter DeviceTvmSoftwareVulnerabilitiesKB on CveId
| summarize arg_max(LastModifiedTime, PublishedDate, VulnerabilityDescription, IsExploitAvailable, EpssScore, AffectedSoftware) by CveId
| project CveId, PublishedDate = format_datetime(PublishedDate, 'yyyy-MM-dd'), VulnerabilityDescription, IsExploitAvailable, EpssScore, AffectedSoftware, LastModifiedTime
"@

    $body = @{ Query = $query } | ConvertTo-Json
    $response = Invoke-RestMethod -Uri $QueryUrl -Headers $Headers -Method Post -Body $body -ErrorAction Stop

    if (-not $response.Results) {
        return [PSCustomObject]@{
            Success = $false
            RecordCount = 0
            OutputFile = $null
            MigratedLegacy = $false
        }
    }

    return Invoke-WithStoreLock -BasePath $OutputPath -StoreName 'advancedhunting' -ScriptBlock {
        Restore-StoreTransaction -BasePath $OutputPath -StoreName 'advancedhunting'

        $store = Initialize-AdvancedHuntingStore -Path $OutputPath -RemoveLegacyFiles
        foreach ($result in $response.Results) {
            $cveId = $result.PSObject.Properties['CveId']?.Value
            if ($cveId) {
                $store.CurrentRecords[$cveId] = $result
            }
        }

        $stageRoot = Join-Path $OutputPath ('.advancedhunting-store-staging-' + [guid]::NewGuid().ToString('N'))
        [void](New-Item -Path $stageRoot -ItemType Directory -Force)

        try {
            $stagedCurrentPath = Join-Path $stageRoot (Split-Path -Leaf $store.CurrentPath)
            Write-NdjsonRecordsFile -Path $stagedCurrentPath -Records $store.CurrentRecords.Values
            Write-Information ("  Advanced Hunting store publish: {0} record(s)" -f $store.CurrentRecords.Count) -InformationAction Continue

            Publish-StoreFilesTransactional -BasePath $OutputPath -StoreName 'advancedhunting' -Files @([PSCustomObject]@{
                StagePath = $stagedCurrentPath
                TargetPath = $store.CurrentPath
            })

            return [PSCustomObject]@{
                Success = $true
                RecordCount = @($response.Results).Count
                OutputFile = $store.CurrentPath
                MigratedLegacy = $store.MigratedLegacy
            }
        }
        finally {
            if (Test-Path -Path $stageRoot) {
                Remove-Item -Path $stageRoot -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

function Get-MdeMachineSnapshotMap {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [Parameter(Mandatory = $true)]
        [string]$BaseApiUrl,

        [Parameter(Mandatory = $true)]
        [string]$ObservedOn
    )

    $url = "$BaseApiUrl/api/machines?`$filter=onboardingStatus eq 'Onboarded'"
    $pageCount = 0
    $snapshotsById = @{}

    do {
        $pageCount++
        $response = Invoke-RestMethod -Uri $url -Headers $Headers -Method Get -ErrorAction Stop

        if ($response.value) {
            foreach ($machine in $response.value) {
                $snapshot = New-MachineSnapshotRecord -Machine $machine -ObservedOn $ObservedOn
                $snapshotsById[$snapshot.id] = $snapshot
            }
        }

        $url = if ($response.PSObject.Properties['@odata.nextLink']) {
            $response.'@odata.nextLink'
        }
        else {
            $null
        }
        $response = $null
    } while ($url)

    return [PSCustomObject]@{
        SnapshotsById = $snapshotsById
        PageCount = $pageCount
    }
}

function Get-MachineStoreRefreshPlan {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$CurrentRecords,

        [Parameter(Mandatory = $true)]
        [hashtable]$FetchedSnapshotsById,

        [Parameter(Mandatory = $true)]
        [string]$ObservedOn
    )

    $changeRecords = [System.Collections.Generic.List[object]]::new()
    $nextCurrentRecords = @{}

    foreach ($snapshot in $FetchedSnapshotsById.Values) {
        $existing = $CurrentRecords[$snapshot.id]
        if (($null -eq $existing) -or ($existing.stateHash -ne $snapshot.stateHash)) {
            $changeRecords.Add($snapshot)
        }

        $nextCurrentRecords[$snapshot.id] = $snapshot
    }

    foreach ($existingId in @($CurrentRecords.Keys)) {
        if (-not $nextCurrentRecords.ContainsKey($existingId)) {
            $changeRecords.Add((New-MachineRemovalRecord -MachineId $existingId -ObservedOn $ObservedOn))
        }
    }

    return [PSCustomObject]@{
        ChangeRecords = $changeRecords
        NextCurrentRecords = $nextCurrentRecords
        MachineCount = $nextCurrentRecords.Count
    }
}

function Publish-MachineStoreState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [hashtable]$Store,

        [Parameter(Mandatory = $true)]
        $ChangeRecords
    )

    $stageRoot = Join-Path $OutputPath ('.machine-store-staging-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $stageRoot -ItemType Directory -Force)

    try {
        $stagedCurrentPath = Join-Path $stageRoot (Split-Path -Leaf $Store.CurrentPath)
        Write-NdjsonRecordsFile -Path $stagedCurrentPath -Records $Store.CurrentRecords.Values
        Write-Information ("  Machine store publish: {0} current record(s), {1} history period(s), {2} change record(s)" -f $Store.CurrentRecords.Count, $Store.HistoryRecordsByPeriod.Count, @($ChangeRecords).Count) -InformationAction Continue

        $filesToPublish = [System.Collections.Generic.List[object]]::new()
        $filesToPublish.Add([PSCustomObject]@{
            StagePath = $stagedCurrentPath
            TargetPath = $Store.CurrentPath
        })

        $outputFiles = [System.Collections.Generic.List[string]]::new()
        $outputFiles.Add($Store.CurrentPath)

        $historyRecordKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($periodKey in @($Store.HistoryRecordsByPeriod.Keys)) {
            foreach ($record in @($Store.HistoryRecordsByPeriod[$periodKey])) {
                [void]$historyRecordKeys.Add((Get-MachineHistoryRecordKey -Record $record))
            }
        }

        foreach ($changeRecord in $ChangeRecords) {
            Add-MachineHistoryRecordToPeriodMap -HistoryRecordsByPeriod $Store.HistoryRecordsByPeriod -RecordKeys $historyRecordKeys -Record $changeRecord
        }

        $publishedHistoryNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($periodKey in @($Store.HistoryRecordsByPeriod.Keys | Sort-Object)) {
            $historyStagePath = Get-MachineHistoryQuarterlyPath -BasePath $stageRoot -PeriodKey $periodKey
            Write-NdjsonRecordsFile -Path $historyStagePath -Records $Store.HistoryRecordsByPeriod[$periodKey]

            $historyTargetPath = Get-MachineHistoryQuarterlyPath -BasePath $OutputPath -PeriodKey $periodKey
            $filesToPublish.Add([PSCustomObject]@{
                StagePath = $historyStagePath
                TargetPath = $historyTargetPath
            })

            $historyName = Split-Path -Leaf $historyTargetPath
            [void]$publishedHistoryNames.Add($historyName)
            $outputFiles.Add($historyTargetPath)
        }

        $removePaths = @(Get-MachineHistoryRemovePaths -BasePath $OutputPath -PublishedHistoryNames $publishedHistoryNames)
        Publish-StoreFilesTransactional -BasePath $OutputPath -StoreName 'machines' -Files @($filesToPublish) -RemovePaths $removePaths

        return [PSCustomObject]@{
            Success = $true
            ChangeCount = $ChangeRecords.Count
            OutputFiles = @($outputFiles)
            MigratedLegacy = $Store.MigratedLegacy
        }
    }
    finally {
        if (Test-Path -Path $stageRoot) {
            Remove-Item -Path $stageRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Invoke-MdeMachineStoreRefresh {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [string]$BaseApiUrl
    )

    $observedOn = Get-Date -Format 'yyyy-MM-dd'
    $snapshotResult = Get-MdeMachineSnapshotMap -Headers $Headers -BaseApiUrl $BaseApiUrl -ObservedOn $observedOn

    return Invoke-WithStoreLock -BasePath $OutputPath -StoreName 'machines' -ScriptBlock {
        Restore-StoreTransaction -BasePath $OutputPath -StoreName 'machines'

        $store = Initialize-MachineHistoryStore -Path $OutputPath -RemoveLegacyFiles
        $refreshPlan = Get-MachineStoreRefreshPlan -CurrentRecords $store.CurrentRecords -FetchedSnapshotsById $snapshotResult.SnapshotsById -ObservedOn $observedOn
        $store.CurrentRecords = $refreshPlan.NextCurrentRecords

        $publishResult = Publish-MachineStoreState -OutputPath $OutputPath -Store $store -ChangeRecords $refreshPlan.ChangeRecords
        return [PSCustomObject]@{
            Success = $true
            MachineCount = $refreshPlan.MachineCount
            ChangeCount = $publishResult.ChangeCount
            PageCount = $snapshotResult.PageCount
            OutputFiles = @($publishResult.OutputFiles)
            MigratedLegacy = $publishResult.MigratedLegacy
        }
    }
}

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
        [string]$FilePath,

        [Parameter(Mandatory = $false)]
        [switch]$InsertLineBreaks
    )

    $bytes = [System.IO.File]::ReadAllBytes($FilePath)
    $formatting = if ($InsertLineBreaks) { [System.Base64FormattingOptions]::InsertLineBreaks } else { [System.Base64FormattingOptions]::None }
    $Writer.Write([System.Convert]::ToBase64String($bytes, $formatting))
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

            [void](Read-CompactJsonReaderValue -Reader $jsonReader)
            $rowCount++
        }

        return $rowCount
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
        }
        else {
            if ([string]::IsNullOrWhiteSpace($VulnsPath) -or -not (Test-Path -LiteralPath $VulnsPath -PathType Leaf)) {
                throw 'Write-CombinedPayloadGzip requires either -VulnsPath or -VulnColumnPaths.'
            }

            $jsonWriter.WritePropertyName('vulnsFormat')
            $jsonWriter.WriteValue('rows-v1')
            $jsonWriter.WritePropertyName('vulns')
            $vulnsReader = [System.IO.StreamReader]::new($VulnsPath, [System.Text.Encoding]::UTF8)
            $vulnsJsonReader = [Newtonsoft.Json.JsonTextReader]::new($vulnsReader)
            [void]$columnReaders.Add($vulnsJsonReader)
            [void]$columnReaders.Add($vulnsReader)
            $jsonWriter.WriteToken($vulnsJsonReader)
        }

        $jsonWriter.WriteEndObject()
        $jsonWriter.Flush()
    }
    finally {
        foreach ($columnDisposable in $columnReaders) {
            $columnDisposable.Dispose()
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
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [switch]$InsertBase64LineBreaks
    )

    $builder = [System.Text.StringBuilder]::new($Template.Length + 262144)
    $position = 0
    foreach ($segment in $Segments) {
        $placeholder = $segment.Placeholder
        $index = $Template.IndexOf($placeholder, $position, [System.StringComparison]::Ordinal)
        if ($index -lt 0) {
            throw "Template placeholder not found: $placeholder"
        }

        [void]$builder.Append($Template.Substring($position, $index - $position))
        if ($segment.ContainsKey('Base64FilePath')) {
            [void]$builder.Append((Get-Base64FileContent -FilePath $segment.Base64FilePath -InsertLineBreaks:$InsertBase64LineBreaks))
        }
        elseif ($segment.ContainsKey('FilePath')) {
            [void]$builder.Append([System.IO.File]::ReadAllText([string]$segment.FilePath, [System.Text.Encoding]::UTF8))
        }
        else {
            [void]$builder.Append([string]$segment.Value)
        }

        $position = $index + $placeholder.Length
    }

    [void]$builder.Append($Template.Substring($position))
    [System.IO.File]::WriteAllText($OutputPath, $builder.ToString(), [System.Text.UTF8Encoding]::new($false))
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

function Write-DashboardArtifacts {
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
            throw 'Write-DashboardArtifacts requires ChartJsBundlePath when SplitAssets is false.'
        }

        if ([string]::IsNullOrWhiteSpace($PdfExportBundlePath) -or -not (Test-Path -LiteralPath $PdfExportBundlePath -PathType Leaf)) {
            throw 'Write-DashboardArtifacts requires PdfExportBundlePath when SplitAssets is false.'
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
                        $rawDescription = $record.PSObject.Properties['VulnerabilityDescription']?.Value
                        $rawAffectedSoftware = $record.PSObject.Properties['AffectedSoftware']?.Value
                        $affectedSoftware = @(ConvertTo-AdvancedHuntingStringArray -Value $rawAffectedSoftware)
                        $ahData[$cveId] = @{
                            PublishedDate = Convert-ToYmdDate -DateValue $pdRaw
                            VulnerabilityDescription = ConvertTo-AdvancedHuntingDescriptionValue -Value $rawDescription
                            EpssScore = $record.PSObject.Properties['EpssScore']?.Value
                            AffectedSoftware = if ($affectedSoftware.Count -gt 0) { @($affectedSoftware) } else { $null }
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
    [void]$builder.AppendLine('dashboard-payload-cache-v2')
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
        Version = 'dashboard-payload-cache-v2'
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
                if ($ahData.AffectedSoftware -and @($ahData.AffectedSoftware).Count -gt 0) {
                    $affSoftwareIndices = [System.Collections.Generic.List[int]]::new()
                    foreach ($sw in @($ahData.AffectedSoftware)) {
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
                                if ($ahData.AffectedSoftware -and @($ahData.AffectedSoftware).Count -gt 0) {
                                    $affSoftwareIndices = [System.Collections.Generic.List[int]]::new()
                                    foreach ($sw in @($ahData.AffectedSoftware)) {
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
    $compactRecordBuffer = $null
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
                $compactRecordBuffer = [System.Collections.Generic.List[object]]::new()
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
                'None' { 4 }
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
                        if ($ahData.AffectedSoftware -and @($ahData.AffectedSoftware).Count -gt 0) {
                            $affSoftwareIndices = [System.Collections.Generic.List[int]]::new()
                            foreach ($sw in @($ahData.AffectedSoftware)) {
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
                if ($compactRecordBuffer) {
                    [void]$compactRecordBuffer.Add(@($compactRecord))
                }
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

    if ((-not $columnWriterSet) -and -not [string]::IsNullOrWhiteSpace($VulnOutputPath) -and (Test-Path -LiteralPath $VulnOutputPath -PathType Leaf)) {
        $actualVulnRowCount = Get-CompactVulnJsonRowCount -Path $VulnOutputPath
        if ($actualVulnRowCount -ne $processedCount) {
            Write-Warning ("  Normalized vulnerability payload row count mismatch (expected {0}, found {1}); rewriting via buffered fallback serializer." -f $processedCount, $actualVulnRowCount)
            if ($compactRecordBuffer) {
                [System.IO.File]::WriteAllText(
                    $VulnOutputPath,
                    ($compactRecordBuffer | ConvertTo-Json -Compress -Depth 6),
                    [System.Text.UTF8Encoding]::new($false)
                )
                $actualVulnRowCount = Get-CompactVulnJsonRowCount -Path $VulnOutputPath
            }

            if ($actualVulnRowCount -ne $processedCount) {
                throw ("Normalized vulnerability payload row count mismatch after rewrite fallback. Expected {0}, found {1} in '{2}'." -f $processedCount, $actualVulnRowCount, $VulnOutputPath)
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
