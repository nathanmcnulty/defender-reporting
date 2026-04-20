#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$DirectoryPath = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'exports'),

    [Parameter(Mandatory = $false)]
    [string]$OutputRoot = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) ('.local\validation-mode-comparison\' + (Get-Date -Format 'yyyyMMdd-HHmmss'))),

    [Parameter(Mandatory = $false)]
    [ValidateRange(15, 3600)]
    [int]$ValidationHeartbeatSeconds = 60,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 64)]
    [int]$ValidationPartitionCompareParallelism = 1,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 60)]
    [int]$PollIntervalSeconds = 5
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $IsWindows) {
    throw 'tests/Invoke-ValidationModeComparison.ps1 currently supports Windows only because it relies on Win32 CIM classes for process and memory sampling.'
}

function Get-TextWithoutAnsiEscape {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Text
    )

    return ([regex]::Replace($Text, "`e\[[0-9;]*m", ''))
}

function Get-AvailableMemoryGB {
    [CmdletBinding()]
    [OutputType([double])]
    param()

    $os = Get-CimInstance Win32_OperatingSystem
    return [math]::Round(($os.FreePhysicalMemory / 1MB), 2)
}

function Get-HeartbeatTimestampText {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    return (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
}

function Get-HeartbeatFileStatus {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [PSCustomObject]@{
            bytes = 0L
            ageSeconds = $null
        }
    }

    $item = Get-Item -LiteralPath $Path
    return [PSCustomObject]@{
        bytes = [int64]$item.Length
        ageSeconds = [math]::Round(((Get-Date).ToUniversalTime() - $item.LastWriteTimeUtc).TotalSeconds, 1)
    }
}

function Write-ModeComparisonHeartbeat {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Stopwatch]$Stopwatch,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$Samples,

        [Parameter(Mandatory = $true)]
        [string]$StdoutPath,

        [Parameter(Mandatory = $true)]
        [int64]$PeakRssBytes,

        [Parameter(Mandatory = $true)]
        [int64]$PeakPrivateBytes
    )

    $lastSample = if ($Samples.Count -gt 0) { $Samples[$Samples.Count - 1] } else { $null }
    $stdoutStatus = Get-HeartbeatFileStatus -Path $StdoutPath
    $availableMemory = if ($null -ne $lastSample) { [double]$lastSample.available_memory_gb } else { Get-AvailableMemoryGB }
    $stdoutAgeText = if ($null -ne $stdoutStatus.ageSeconds) { ('{0:N1}s' -f $stdoutStatus.ageSeconds) } else { 'n/a' }

    $message = "[{0}] Validation comparison heartbeat ({1}): elapsed={2} peak-rss={3}GB peak-private={4}GB samples={5} available={6}GB stdout-bytes={7} stdout-age={8}" -f @(
        (Get-HeartbeatTimestampText)
        $Name
        $Stopwatch.Elapsed.ToString('hh\:mm\:ss')
        [math]::Round(($PeakRssBytes / 1GB), 3)
        [math]::Round(($PeakPrivateBytes / 1GB), 3)
        $Samples.Count
        $availableMemory
        $stdoutStatus.bytes
        $stdoutAgeText
    )
    Write-Host $message
}

function Get-ProcessTree {
    [CmdletBinding()]
    [OutputType([System.Diagnostics.Process[]])]
    param(
        [Parameter(Mandatory = $true)]
        [int]$RootProcessId
    )

    $processById = @{}
    foreach ($process in @(Get-Process -ErrorAction SilentlyContinue)) {
        $processById[$process.Id] = $process
    }

    $childrenByParent = @{}
    foreach ($process in @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) {
        $parentId = [int]$process.ParentProcessId
        if (-not $childrenByParent.ContainsKey($parentId)) {
            $childrenByParent[$parentId] = [System.Collections.Generic.List[int]]::new()
        }

        $childrenByParent[$parentId].Add([int]$process.ProcessId)
    }

    $queue = [System.Collections.Generic.Queue[int]]::new()
    $seen = [System.Collections.Generic.HashSet[int]]::new()
    $queue.Enqueue($RootProcessId)

    while ($queue.Count -gt 0) {
        $currentId = $queue.Dequeue()
        if (-not $seen.Add($currentId)) {
            continue
        }

        if ($childrenByParent.ContainsKey($currentId)) {
            foreach ($childId in $childrenByParent[$currentId]) {
                $queue.Enqueue($childId)
            }
        }
    }

    $processes = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()
    foreach ($processId in $seen) {
        if ($processById.ContainsKey($processId)) {
            $processes.Add($processById[$processId]) | Out-Null
        }
    }

    return @($processes | Sort-Object -Property Id)
}

function Add-MeasurementSample {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$Samples,

        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Process]$Process,

        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Stopwatch]$Stopwatch,

        [Parameter(Mandatory = $true)]
        [ref]$PeakRssBytes,

        [Parameter(Mandatory = $true)]
        [ref]$PeakRssAt,

        [Parameter(Mandatory = $true)]
        [ref]$PeakPrivateBytes,

        [Parameter(Mandatory = $true)]
        [ref]$PeakPrivateAt
    )

    $tree = @(Get-ProcessTree -RootProcessId $Process.Id)
    if ($tree.Count -eq 0) {
        try {
            $null = $Process.WorkingSet64
            $tree = @($Process)
        }
        catch {
            return
        }
    }

    $rssBytes = [int64](($tree | Measure-Object -Property WorkingSet64 -Sum).Sum)
    $privateBytes = [int64](($tree | Measure-Object -Property PrivateMemorySize64 -Sum).Sum)
    $elapsedSeconds = [math]::Round($Stopwatch.Elapsed.TotalSeconds, 2)
    if ($rssBytes -gt $PeakRssBytes.Value) {
        $PeakRssBytes.Value = $rssBytes
        $PeakRssAt.Value = $elapsedSeconds
    }
    if ($privateBytes -gt $PeakPrivateBytes.Value) {
        $PeakPrivateBytes.Value = $privateBytes
        $PeakPrivateAt.Value = $elapsedSeconds
    }

    $Samples.Add([PSCustomObject]@{
        elapsed_seconds = $elapsedSeconds
        process_count = $tree.Count
        tree_rss_bytes = $rssBytes
        tree_private_bytes = $privateBytes
        available_memory_gb = Get-AvailableMemoryGB
    }) | Out-Null
}

function Write-LogTail {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Label,

        [Parameter(Mandatory = $false)]
        [int]$TailLineCount = 120
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return
    }

    $tailLines = @(Get-Content -Path $Path -Tail $TailLineCount)
    if ($tailLines.Count -eq 0) {
        return
    }

    Write-Host ''
    Write-Host ("--- {0} (last {1} line(s)) ---" -f $Label, $tailLines.Count)
    foreach ($line in $tailLines) {
        Write-Host $line
    }
}

function Get-ValidationAuditSummary {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Audit
    )

    if ($null -eq $Audit) {
        return $null
    }

    $semanticParity = if ($Audit.PSObject.Properties['SemanticParity']) {
        $Audit.SemanticParity
    }
    else {
        $null
    }

    return [PSCustomObject]@{
        auditMode = if ($Audit.PSObject.Properties['AuditMode']) { [string]$Audit.AuditMode } else { $null }
        rowMatch = if ($Audit.PSObject.Properties['RowComparison']) { [bool]$Audit.RowComparison.Match } else { $null }
        payloadByteParityMatch = if ($null -ne $semanticParity -and $semanticParity.PSObject.Properties['PayloadByteParityMatch']) { [bool]$semanticParity.PayloadByteParityMatch } else { $null }
        comparisonStorage = if ($null -ne $semanticParity -and $semanticParity.PSObject.Properties['ComparisonStorage']) { [string]$semanticParity.ComparisonStorage } else { $null }
        comparisonPayloadSource = if ($null -ne $semanticParity -and $semanticParity.PSObject.Properties['ComparisonPayloadSource']) { [string]$semanticParity.ComparisonPayloadSource } else { $null }
        attestationUsed = if ($null -ne $semanticParity -and $semanticParity.PSObject.Properties['AttestationUsed']) { [bool]$semanticParity.AttestationUsed } else { $false }
        phaseTimings = if ($Audit.PSObject.Properties['PhaseTimings']) { $Audit.PhaseTimings } elseif ($null -ne $semanticParity -and $semanticParity.PSObject.Properties['PhaseTimings']) { $semanticParity.PhaseTimings } else { $null }
    }
}

function Get-LocalPhaseSummaryFromLog {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return @()
    }

    $phaseByName = [ordered]@{}
    foreach ($rawLine in Get-Content -Path $Path) {
        $line = Get-TextWithoutAnsiEscape -Text ([string]$rawLine)
        if ($line -match '^\s*--- Local Phase: (?<name>.+?) ---\s*$') {
            $phaseName = [string]$matches.name
            if (-not $phaseByName.Contains($phaseName)) {
                $phaseByName[$phaseName] = [ordered]@{
                    name = $phaseName
                    status = 'started'
                    elapsedSeconds = $null
                    startWorkingSetMB = $null
                    endWorkingSetMB = $null
                    startGcHeapMB = $null
                    endGcHeapMB = $null
                }
            }

            continue
        }

        if ($line -match '^\s*\[(?<name>.+?)/(?<checkpoint>start|end)\] Memory .*?Working set: (?<working>[0-9.]+)MB\s*\|\s*GC heap: (?<heap>[0-9.]+)MB\s*$') {
            $phaseName = [string]$matches.name
            if (-not $phaseByName.Contains($phaseName)) {
                $phaseByName[$phaseName] = [ordered]@{ name = $phaseName }
            }

            $phaseEntry = $phaseByName[$phaseName]
            $checkpoint = [string]$matches.checkpoint
            $workingSetMB = [double]$matches.working
            $gcHeapMB = [double]$matches.heap
            if ($checkpoint -eq 'start') {
                $phaseEntry.startWorkingSetMB = $workingSetMB
                $phaseEntry.startGcHeapMB = $gcHeapMB
            }
            else {
                $phaseEntry.endWorkingSetMB = $workingSetMB
                $phaseEntry.endGcHeapMB = $gcHeapMB
            }

            continue
        }

        if ($line -match '^\s*\[(?<name>.+?)\] Elapsed: (?<seconds>[0-9.,]+)s(?:\s*\((?<status>[^)]+)\))?\s*$') {
            $phaseName = [string]$matches.name
            if (-not $phaseByName.Contains($phaseName)) {
                $phaseByName[$phaseName] = [ordered]@{ name = $phaseName }
            }

            $phaseEntry = $phaseByName[$phaseName]
            $phaseEntry.elapsedSeconds = [double](($matches.seconds -replace ',', ''))
            $phaseEntry.status = if ($matches.status) { [string]$matches.status } else { 'completed' }
        }
    }

    return @(
        foreach ($phaseEntry in $phaseByName.Values) {
            [PSCustomObject]@{
                name = [string]$phaseEntry.name
                status = if ($phaseEntry.Contains('status')) { [string]$phaseEntry.status } else { 'unknown' }
                elapsedSeconds = if ($phaseEntry.Contains('elapsedSeconds')) { $phaseEntry.elapsedSeconds } else { $null }
                startWorkingSetMB = if ($phaseEntry.Contains('startWorkingSetMB')) { $phaseEntry.startWorkingSetMB } else { $null }
                endWorkingSetMB = if ($phaseEntry.Contains('endWorkingSetMB')) { $phaseEntry.endWorkingSetMB } else { $null }
                startGcHeapMB = if ($phaseEntry.Contains('startGcHeapMB')) { $phaseEntry.startGcHeapMB } else { $null }
                endGcHeapMB = if ($phaseEntry.Contains('endGcHeapMB')) { $phaseEntry.endGcHeapMB } else { $null }
            }
        }
    )
}

function Get-ValidationPhaseSummaryFromAudit {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Audit
    )

    if ($null -eq $Audit) {
        return @()
    }

    $phaseTimings = if ($Audit.PSObject.Properties['PhaseTimings']) {
        $Audit.PhaseTimings
    }
    elseif ($Audit.PSObject.Properties['SemanticParity'] -and $Audit.SemanticParity.PSObject.Properties['PhaseTimings']) {
        $Audit.SemanticParity.PhaseTimings
    }
    else {
        $null
    }

    if ($null -eq $phaseTimings) {
        return @()
    }

    $phaseMap = [ordered]@{
        MachineLoadElapsedSeconds = 'Machine load'
        AdvancedHuntingLoadElapsedSeconds = 'Advanced Hunting load'
        SourceMaterializationElapsedSeconds = 'Source materialization'
        PayloadLoadElapsedSeconds = 'Payload load'
        VendorIndexElapsedSeconds = 'Vendor index'
        SourceSignatureElapsedSeconds = 'Source signatures'
        PayloadSignatureElapsedSeconds = 'Payload signatures'
        RowComparisonElapsedSeconds = 'Row comparison'
        EnrichmentAuditElapsedSeconds = 'Enrichment audit'
        ReportComparisonsElapsedSeconds = 'Report comparisons'
        DuplicateIdentityElapsedSeconds = 'Duplicate identity audit'
        OpenStateElapsedSeconds = 'Open state audit'
        ComparisonElapsedSeconds = 'Comparison'
        BaselineAuditElapsedSeconds = 'Baseline audit'
        BaselineCoverageElapsedSeconds = 'Baseline coverage'
        LegacyFixtureRegressionElapsedSeconds = 'Legacy fixture regression'
    }

    return @(
        foreach ($propertyName in $phaseMap.Keys) {
            if (-not $phaseTimings.PSObject.Properties[$propertyName]) {
                continue
            }

            $value = $phaseTimings.$propertyName
            if ($null -eq $value -or [double]$value -le 0) {
                continue
            }

            [PSCustomObject]@{
                name = [string]$phaseMap[$propertyName]
                property = [string]$propertyName
                elapsedSeconds = [double]$value
            }
        }
    )
}

function Get-HotPhaseSummary {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$GeneratorPhases,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$ValidationPhases
    )

    $combined = [System.Collections.Generic.List[object]]::new()
    foreach ($phase in @($GeneratorPhases | Where-Object { $null -ne $_.elapsedSeconds })) {
        $combined.Add([PSCustomObject]@{
            scope = 'generator'
            name = [string]$phase.name
            elapsedSeconds = [double]$phase.elapsedSeconds
        }) | Out-Null
    }

    foreach ($phase in @($ValidationPhases | Where-Object { $null -ne $_.elapsedSeconds })) {
        $combined.Add([PSCustomObject]@{
            scope = 'validation'
            name = [string]$phase.name
            elapsedSeconds = [double]$phase.elapsedSeconds
        }) | Out-Null
    }

    return @($combined | Sort-Object -Property elapsedSeconds -Descending)
}

function Invoke-ValidationModeRun {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$RepoRoot,

        [Parameter(Mandatory = $true)]
        [string[]]$ArgumentList,

        [Parameter(Mandatory = $true)]
        [string]$ModeOutputRoot,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$DashboardPath,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$AuditPath,

        [Parameter(Mandatory = $false)]
        [switch]$ResetDashboardPath,

        [Parameter(Mandatory = $false)]
        [switch]$ResetAuditPath,

        [Parameter(Mandatory = $true)]
        [int]$PollIntervalSeconds
    )

    if (-not (Test-Path -LiteralPath $ModeOutputRoot -PathType Container)) {
        $null = New-Item -Path $ModeOutputRoot -ItemType Directory -Force
    }

    $stdoutPath = Join-Path $ModeOutputRoot ($Name + '.stdout.log')
    $stderrPath = Join-Path $ModeOutputRoot ($Name + '.stderr.log')

    $pathsToRemove = [System.Collections.Generic.List[string]]::new()
    $pathsToRemove.Add($stdoutPath) | Out-Null
    $pathsToRemove.Add($stderrPath) | Out-Null
    if ($ResetDashboardPath -and -not [string]::IsNullOrWhiteSpace($DashboardPath)) {
        $pathsToRemove.Add($DashboardPath) | Out-Null
    }
    if ($ResetAuditPath -and -not [string]::IsNullOrWhiteSpace($AuditPath)) {
        $pathsToRemove.Add($AuditPath) | Out-Null
    }

    foreach ($path in $pathsToRemove) {
        if ([string]::IsNullOrWhiteSpace($path)) {
            continue
        }

        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Write-Host ''
    Write-Host ("Running validation mode: {0}" -f $Name)
    $process = Start-Process -FilePath 'pwsh' -ArgumentList $ArgumentList -WorkingDirectory $RepoRoot -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $samples = [System.Collections.Generic.List[object]]::new()
    $peakRssBytes = [int64]0
    $peakRssAt = [double]0
    $peakPrivateBytes = [int64]0
    $peakPrivateAt = [double]0

    Add-MeasurementSample -Samples $samples -Process $process -Stopwatch $stopwatch -PeakRssBytes ([ref]$peakRssBytes) -PeakRssAt ([ref]$peakRssAt) -PeakPrivateBytes ([ref]$peakPrivateBytes) -PeakPrivateAt ([ref]$peakPrivateAt)
    Write-ModeComparisonHeartbeat -Name $Name -Stopwatch $stopwatch -Samples $samples -StdoutPath $stdoutPath -PeakRssBytes $peakRssBytes -PeakPrivateBytes $peakPrivateBytes

    while (-not $process.HasExited) {
        Start-Sleep -Seconds $PollIntervalSeconds
        $process.Refresh()
        Add-MeasurementSample -Samples $samples -Process $process -Stopwatch $stopwatch -PeakRssBytes ([ref]$peakRssBytes) -PeakRssAt ([ref]$peakRssAt) -PeakPrivateBytes ([ref]$peakPrivateBytes) -PeakPrivateAt ([ref]$peakPrivateAt)
        if (-not $process.HasExited) {
            Write-ModeComparisonHeartbeat -Name $Name -Stopwatch $stopwatch -Samples $samples -StdoutPath $stdoutPath -PeakRssBytes $peakRssBytes -PeakPrivateBytes $peakPrivateBytes
        }
    }

    $process.WaitForExit()
    $process.Refresh()
    Add-MeasurementSample -Samples $samples -Process $process -Stopwatch $stopwatch -PeakRssBytes ([ref]$peakRssBytes) -PeakRssAt ([ref]$peakRssAt) -PeakPrivateBytes ([ref]$peakPrivateBytes) -PeakPrivateAt ([ref]$peakPrivateAt)
    $stopwatch.Stop()

    $generatorPhases = Get-LocalPhaseSummaryFromLog -Path $stdoutPath
    $audit = if (-not [string]::IsNullOrWhiteSpace($AuditPath) -and (Test-Path -LiteralPath $AuditPath -PathType Leaf)) {
        Get-Content -Path $AuditPath -Raw | ConvertFrom-Json -Depth 100
    }
    else {
        $null
    }
    $auditSummary = Get-ValidationAuditSummary -Audit $audit
    $validationPhases = Get-ValidationPhaseSummaryFromAudit -Audit $audit
    $hotPhases = Get-HotPhaseSummary -GeneratorPhases @($generatorPhases) -ValidationPhases @($validationPhases)

    $observations = [System.Collections.Generic.List[string]]::new()
    $topPhase = @($hotPhases | Select-Object -First 1)
    if ($topPhase.Count -gt 0) {
        $observations.Add(("Dominant phase [{0}] {1}: {2:N2}s." -f $topPhase[0].scope, $topPhase[0].name, $topPhase[0].elapsedSeconds)) | Out-Null
    }
    if ($null -ne $auditSummary -and $auditSummary.attestationUsed) {
        $observations.Add('Validation reused a semantic attestation.') | Out-Null
    }

    $result = [PSCustomObject]@{
        name = $Name
        command = @('pwsh') + $ArgumentList
        status = if ($process.ExitCode -eq 0) { 'success' } else { 'failure' }
        exitCode = $process.ExitCode
        processMetrics = [PSCustomObject]@{
            elapsedSeconds = [math]::Round($stopwatch.Elapsed.TotalSeconds, 2)
            peakTreeRssBytes = $peakRssBytes
            peakTreeRssGb = [math]::Round(($peakRssBytes / 1GB), 3)
            peakTreeRssAtSeconds = $peakRssAt
            peakTreePrivateBytes = $peakPrivateBytes
            peakTreePrivateGb = [math]::Round(($peakPrivateBytes / 1GB), 3)
            peakTreePrivateAtSeconds = $peakPrivateAt
            sampleCount = $samples.Count
        }
        artifacts = [PSCustomObject]@{
            modeOutputRoot = $ModeOutputRoot
            dashboardPath = if (-not [string]::IsNullOrWhiteSpace($DashboardPath) -and (Test-Path -LiteralPath $DashboardPath -PathType Leaf)) { $DashboardPath } else { $null }
            auditPath = if (-not [string]::IsNullOrWhiteSpace($AuditPath) -and (Test-Path -LiteralPath $AuditPath -PathType Leaf)) { $AuditPath } else { $null }
            stdoutPath = $stdoutPath
            stderrPath = $stderrPath
        }
        validationAuditSummary = $auditSummary
        generatorPhases = @($generatorPhases)
        validationPhases = @($validationPhases)
        hotPhases = @($hotPhases)
        observations = @($observations)
        samples = @($samples)
    }

    if ($process.ExitCode -ne 0) {
        Write-LogTail -Path $stdoutPath -Label ($Name + ' stdout')
        Write-LogTail -Path $stderrPath -Label ($Name + ' stderr')
        throw "Validation mode '$Name' exited with code $($process.ExitCode)."
    }

    return $result
}

$repoRoot = Split-Path -Path $PSScriptRoot -Parent
$dashboardScript = Join-Path $repoRoot 'Generate-VulnerabilityDashboard.ps1'
$resolvedDirectoryPath = [System.IO.Path]::GetFullPath($DirectoryPath)
$resolvedOutputRoot = [System.IO.Path]::GetFullPath($OutputRoot)

if (-not (Test-Path -LiteralPath $resolvedDirectoryPath -PathType Container)) {
    throw "Directory '$resolvedDirectoryPath' was not found."
}

if (-not (Test-Path -LiteralPath $resolvedOutputRoot -PathType Container)) {
    $null = New-Item -Path $resolvedOutputRoot -ItemType Directory -Force
}

$warmupRoot = Join-Path $resolvedOutputRoot 'normalize-only-warmup'
$warmupPayloadPath = Join-Path $warmupRoot 'normalized-payload.json.gz'
$warmupManifestPath = Join-Path $warmupRoot 'normalized-payload.manifest.json'
$warmupOutputPath = Join-Path $warmupRoot 'Warmup.html'

$packageRoot = Join-Path $resolvedOutputRoot 'package-only'
$packageOutputPath = Join-Path $packageRoot 'VulnerabilityDashboard.html'

$validateForceRoot = Join-Path $resolvedOutputRoot 'validate-only-forcefull'
$validateForceAuditPath = Join-Path $validateForceRoot 'dashboard-audit.json'

$validateAttestedRoot = Join-Path $resolvedOutputRoot 'validate-only-attested'
$validateAttestedAuditPath = Join-Path $validateAttestedRoot 'dashboard-audit.json'

$fullForceRoot = Join-Path $resolvedOutputRoot 'full-generate-forcefull'
$fullForceOutputPath = Join-Path $fullForceRoot 'VulnerabilityDashboard.html'
$fullForceAuditPath = Join-Path $fullForceRoot 'dashboard-audit.json'

$fullDefaultRoot = Join-Path $resolvedOutputRoot 'full-generate-default'
$fullDefaultOutputPath = Join-Path $fullDefaultRoot 'VulnerabilityDashboard.html'
$fullDefaultAuditPath = Join-Path $fullDefaultRoot 'dashboard-audit.json'

$reportPath = Join-Path $resolvedOutputRoot 'validation-mode-comparison.json'
if (Test-Path -LiteralPath $reportPath -PathType Leaf) {
    Remove-Item -LiteralPath $reportPath -Force
}

Write-Output 'Running validation mode comparison...'
Write-Output ("  Dataset: {0}" -f $resolvedDirectoryPath)
Write-Output ("  Output root: {0}" -f $resolvedOutputRoot)

$runs = [System.Collections.Generic.List[object]]::new()

$warmupArgs = @(
    '-NoProfile'
    '-File', $dashboardScript
    '-DirectoryPath', $resolvedDirectoryPath
    '-OutputPath', $warmupOutputPath
    '-ExportMachineData:$false'
    '-NormalizeOnly'
    '-NormalizedPayloadOutputPath', $warmupPayloadPath
    '-NormalizedPayloadManifestOutputPath', $warmupManifestPath
)
$runs.Add((Invoke-ValidationModeRun -Name 'normalize-only-warmup' -RepoRoot $repoRoot -ArgumentList $warmupArgs -ModeOutputRoot $warmupRoot -DashboardPath '' -AuditPath '' -PollIntervalSeconds $PollIntervalSeconds)) | Out-Null

$packageArgs = @(
    '-NoProfile'
    '-File', $dashboardScript
    '-DirectoryPath', $resolvedDirectoryPath
    '-OutputPath', $packageOutputPath
    '-ExportMachineData:$false'
    '-PackageOnly'
    '-NormalizedPayloadInputPath', $warmupPayloadPath
    '-NormalizedPayloadManifestInputPath', $warmupManifestPath
)
$runs.Add((Invoke-ValidationModeRun -Name 'package-only' -RepoRoot $repoRoot -ArgumentList $packageArgs -ModeOutputRoot $packageRoot -DashboardPath $packageOutputPath -AuditPath '' -ResetDashboardPath -PollIntervalSeconds $PollIntervalSeconds)) | Out-Null

$validateForceArgs = @(
    '-NoProfile'
    '-File', $dashboardScript
    '-DirectoryPath', $resolvedDirectoryPath
    '-OutputPath', $packageOutputPath
    '-ValidateOnly'
    '-ValidationOutputPath', $validateForceAuditPath
    '-ValidationHeartbeatSeconds', $ValidationHeartbeatSeconds
    '-ValidationPartitionCompareParallelism', $ValidationPartitionCompareParallelism
    '-ForceFullValidation'
)
$runs.Add((Invoke-ValidationModeRun -Name 'validate-only-forcefull' -RepoRoot $repoRoot -ArgumentList $validateForceArgs -ModeOutputRoot $validateForceRoot -DashboardPath $packageOutputPath -AuditPath $validateForceAuditPath -ResetAuditPath -PollIntervalSeconds $PollIntervalSeconds)) | Out-Null

$validateAttestedArgs = @(
    '-NoProfile'
    '-File', $dashboardScript
    '-DirectoryPath', $resolvedDirectoryPath
    '-OutputPath', $packageOutputPath
    '-ValidateOnly'
    '-ValidationOutputPath', $validateAttestedAuditPath
    '-ValidationHeartbeatSeconds', $ValidationHeartbeatSeconds
    '-ValidationPartitionCompareParallelism', $ValidationPartitionCompareParallelism
)
$runs.Add((Invoke-ValidationModeRun -Name 'validate-only-attested' -RepoRoot $repoRoot -ArgumentList $validateAttestedArgs -ModeOutputRoot $validateAttestedRoot -DashboardPath $packageOutputPath -AuditPath $validateAttestedAuditPath -ResetAuditPath -PollIntervalSeconds $PollIntervalSeconds)) | Out-Null

$fullForceArgs = @(
    '-NoProfile'
    '-File', $dashboardScript
    '-DirectoryPath', $resolvedDirectoryPath
    '-OutputPath', $fullForceOutputPath
    '-ExportMachineData:$false'
    '-Validate'
    '-ValidationOutputPath', $fullForceAuditPath
    '-ValidationHeartbeatSeconds', $ValidationHeartbeatSeconds
    '-ValidationPartitionCompareParallelism', $ValidationPartitionCompareParallelism
    '-ForceFullValidation'
)
$runs.Add((Invoke-ValidationModeRun -Name 'full-generate-forcefull' -RepoRoot $repoRoot -ArgumentList $fullForceArgs -ModeOutputRoot $fullForceRoot -DashboardPath $fullForceOutputPath -AuditPath $fullForceAuditPath -ResetDashboardPath -ResetAuditPath -PollIntervalSeconds $PollIntervalSeconds)) | Out-Null

$fullDefaultArgs = @(
    '-NoProfile'
    '-File', $dashboardScript
    '-DirectoryPath', $resolvedDirectoryPath
    '-OutputPath', $fullDefaultOutputPath
    '-ExportMachineData:$false'
    '-Validate'
    '-ValidationOutputPath', $fullDefaultAuditPath
    '-ValidationHeartbeatSeconds', $ValidationHeartbeatSeconds
    '-ValidationPartitionCompareParallelism', $ValidationPartitionCompareParallelism
)
$runs.Add((Invoke-ValidationModeRun -Name 'full-generate-default' -RepoRoot $repoRoot -ArgumentList $fullDefaultArgs -ModeOutputRoot $fullDefaultRoot -DashboardPath $fullDefaultOutputPath -AuditPath $fullDefaultAuditPath -ResetDashboardPath -ResetAuditPath -PollIntervalSeconds $PollIntervalSeconds)) | Out-Null

$runByName = @{}
foreach ($run in $runs) {
    $runByName[[string]$run.name] = $run
}

$validateForceRun = $runByName['validate-only-forcefull']
$validateAttestedRun = $runByName['validate-only-attested']
$fullForceRun = $runByName['full-generate-forcefull']
$fullDefaultRun = $runByName['full-generate-default']

$summary = [PSCustomObject]@{
    validateOnlyForceFullSeconds = if ($null -ne $validateForceRun) { $validateForceRun.processMetrics.elapsedSeconds } else { $null }
    validateOnlyAttestedSeconds = if ($null -ne $validateAttestedRun) { $validateAttestedRun.processMetrics.elapsedSeconds } else { $null }
    fullGenerateForceFullSeconds = if ($null -ne $fullForceRun) { $fullForceRun.processMetrics.elapsedSeconds } else { $null }
    fullGenerateDefaultSeconds = if ($null -ne $fullDefaultRun) { $fullDefaultRun.processMetrics.elapsedSeconds } else { $null }
    attestedValidationSavingsSeconds = if ($null -ne $validateForceRun -and $null -ne $validateAttestedRun) { [math]::Round(($validateForceRun.processMetrics.elapsedSeconds - $validateAttestedRun.processMetrics.elapsedSeconds), 2) } else { $null }
    attestedFullRunSavingsSeconds = if ($null -ne $fullForceRun -and $null -ne $fullDefaultRun) { [math]::Round(($fullForceRun.processMetrics.elapsedSeconds - $fullDefaultRun.processMetrics.elapsedSeconds), 2) } else { $null }
    maxPeakRssGb = [math]::Round((@($runs | ForEach-Object { $_.processMetrics.peakTreeRssGb } | Measure-Object -Maximum).Maximum), 3)
}

$report = [PSCustomObject]@{
    generatedOnUtc = [datetime]::UtcNow.ToString('o')
    datasetPath = $resolvedDirectoryPath
    outputRoot = $resolvedOutputRoot
    validationHeartbeatSeconds = $ValidationHeartbeatSeconds
    validationPartitionCompareParallelism = $ValidationPartitionCompareParallelism
    pollIntervalSeconds = $PollIntervalSeconds
    runs = @($runs)
    summary = $summary
}

$report | ConvertTo-Json -Depth 20 | Set-Content -Path $reportPath -Encoding utf8

Write-Output ''
Write-Output 'Validation mode comparison completed.'
Write-Output ("  Force-full validate-only: {0}s" -f $summary.validateOnlyForceFullSeconds)
Write-Output ("  Attested validate-only: {0}s" -f $summary.validateOnlyAttestedSeconds)
Write-Output ("  Force-full end-to-end: {0}s" -f $summary.fullGenerateForceFullSeconds)
Write-Output ("  Default end-to-end: {0}s" -f $summary.fullGenerateDefaultSeconds)
Write-Output ("  Attested validation savings: {0}s" -f $summary.attestedValidationSavingsSeconds)
Write-Output ("  Report: {0}" -f $reportPath)