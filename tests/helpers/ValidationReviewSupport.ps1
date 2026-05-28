function Invoke-GeneratedArtifactValidation {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SelfContainedPath,

        [Parameter(Mandatory = $true)]
        [string]$HostedPath
    )

    $validatorScriptPath = Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'Validate-DashboardGeneratedArtifacts.js'
    if (-not (Test-Path -LiteralPath $validatorScriptPath -PathType Leaf)) {
        throw "Artifact validator '$validatorScriptPath' was not found."
    }

    $nodeCommand = Get-Command -Name 'node' -ErrorAction Stop
    & $nodeCommand.Source $validatorScriptPath $SelfContainedPath $HostedPath

    $validatorExitCode = [int]$global:LASTEXITCODE
    if ($validatorExitCode -ne 0) {
        throw "Generated artifact validation failed with exit code $validatorExitCode."
    }

    return [PSCustomObject]@{
        mode = 'generated-artifact-parity'
        validatorScriptPath = [System.IO.Path]::GetFullPath($validatorScriptPath)
        selfContainedPath = [System.IO.Path]::GetFullPath($SelfContainedPath)
        hostedPath = [System.IO.Path]::GetFullPath($HostedPath)
        hostedAssetsPath = Join-Path (Split-Path -Path (Resolve-Path -LiteralPath $HostedPath).Path -Parent) (([System.IO.Path]::GetFileNameWithoutExtension($HostedPath)) + '.assets')
        passed = $true
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
                    startPrivateMemoryMB = $null
                    endPrivateMemoryMB = $null
                    startHandleCount = $null
                    endHandleCount = $null
                    startThreadCount = $null
                    endThreadCount = $null
                    checkpoints = [System.Collections.Generic.List[object]]::new()
                }
            }

            continue
        }

        if ($line -match '^\s*\[(?<name>.+?)/(?<checkpoint>start|end)\] Memory .*?Working set: (?<working>[0-9.]+)MB\s*\|\s*GC heap: (?<heap>[0-9.]+)MB\s*$') {
            $phaseName = [string]$matches.name
            if (-not $phaseByName.Contains($phaseName)) {
                $phaseByName[$phaseName] = [ordered]@{
                    name = $phaseName
                    checkpoints = [System.Collections.Generic.List[object]]::new()
                }
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

        if ($line -match '^\s*\[(?<name>.+?)/(?<checkpoint>start|end)\] Memory details - Private: (?<private>[0-9.]+)MB\s*\|\s*Handles: (?<handles>[0-9]+)\s*\|\s*Threads: (?<threads>[0-9]+)\s*$') {
            $phaseName = [string]$matches.name
            if (-not $phaseByName.Contains($phaseName)) {
                $phaseByName[$phaseName] = [ordered]@{
                    name = $phaseName
                    checkpoints = [System.Collections.Generic.List[object]]::new()
                }
            }

            $phaseEntry = $phaseByName[$phaseName]
            $checkpoint = [string]$matches.checkpoint
            $privateMemoryMB = [double]$matches.private
            $handleCount = [int]$matches.handles
            $threadCount = [int]$matches.threads
            if ($checkpoint -eq 'start') {
                $phaseEntry.startPrivateMemoryMB = $privateMemoryMB
                $phaseEntry.startHandleCount = $handleCount
                $phaseEntry.startThreadCount = $threadCount
            }
            else {
                $phaseEntry.endPrivateMemoryMB = $privateMemoryMB
                $phaseEntry.endHandleCount = $handleCount
                $phaseEntry.endThreadCount = $threadCount
            }

            continue
        }

        if ($line -match '^\s*\[(?<name>.+?)/(?<checkpoint>.+?)\] Retained state - (?<values>.+)\s*$') {
            $phaseName = [string]$matches.name
            $checkpointName = [string]$matches.checkpoint
            if (-not $phaseByName.Contains($phaseName)) {
                $phaseByName[$phaseName] = [ordered]@{
                    name = $phaseName
                    checkpoints = [System.Collections.Generic.List[object]]::new()
                }
            }

            $phaseEntry = $phaseByName[$phaseName]
            if (-not $phaseEntry.Contains('checkpoints')) {
                $phaseEntry.checkpoints = [System.Collections.Generic.List[object]]::new()
            }

            $parsedValues = [ordered]@{}
            foreach ($pairText in @(([string]$matches.values) -split '\s+\|\s+')) {
                if ([string]::IsNullOrWhiteSpace($pairText)) {
                    continue
                }

                $pairParts = @($pairText -split '=', 2)
                if ($pairParts.Count -ne 2) {
                    continue
                }

                $rawKey = [string]$pairParts[0]
                $rawValue = [string]$pairParts[1]
                $value = switch -Regex ($rawValue) {
                    '^(true|false)$' { [bool]::Parse($rawValue); break }
                    '^-?\d+$' { [int64]$rawValue; break }
                    '^-?\d+\.\d+$' { [double]$rawValue; break }
                    default { $rawValue }
                }
                $parsedValues[$rawKey] = $value
            }

            $phaseEntry.checkpoints.Add([PSCustomObject]@{
                    checkpoint = $checkpointName
                    values = [PSCustomObject]$parsedValues
                }) | Out-Null
            continue
        }

        if ($line -match '^\s*\[(?<name>.+?)\] Elapsed: (?<seconds>[0-9.,]+)s(?:\s*\((?<status>[^)]+)\))?\s*$') {
            $phaseName = [string]$matches.name
            if (-not $phaseByName.Contains($phaseName)) {
                $phaseByName[$phaseName] = [ordered]@{
                    name = $phaseName
                    checkpoints = [System.Collections.Generic.List[object]]::new()
                }
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
                startPrivateMemoryMB = if ($phaseEntry.Contains('startPrivateMemoryMB')) { $phaseEntry.startPrivateMemoryMB } else { $null }
                endPrivateMemoryMB = if ($phaseEntry.Contains('endPrivateMemoryMB')) { $phaseEntry.endPrivateMemoryMB } else { $null }
                startHandleCount = if ($phaseEntry.Contains('startHandleCount')) { $phaseEntry.startHandleCount } else { $null }
                endHandleCount = if ($phaseEntry.Contains('endHandleCount')) { $phaseEntry.endHandleCount } else { $null }
                startThreadCount = if ($phaseEntry.Contains('startThreadCount')) { $phaseEntry.startThreadCount } else { $null }
                endThreadCount = if ($phaseEntry.Contains('endThreadCount')) { $phaseEntry.endThreadCount } else { $null }
                checkpoints = if ($phaseEntry.Contains('checkpoints')) { @($phaseEntry.checkpoints) } else { @() }
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

    Write-Output ''
    Write-Output ("--- {0} (last {1} line(s)) ---" -f $Label, $tailLines.Count)
    foreach ($line in $tailLines) {
        Write-Output $line
    }
}
