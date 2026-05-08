#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Name,

    [Parameter(Mandatory = $true)]
    [string]$SyntheticOutputPath,

    [Parameter(Mandatory = $true)]
    [string]$DashboardOutputPath,

    [Parameter(Mandatory = $false)]
    [string]$ReportOutputPath,

    [Parameter(Mandatory = $false)]
    [switch]$ClearDashboardCache,

    [Parameter(Mandatory = $false)]
    [switch]$Validate,

    [Parameter(Mandatory = $false)]
    [ValidateSet('artifacts', 'semantic')]
    [string]$ValidationMode = 'artifacts',

    [Parameter(Mandatory = $false)]
    [switch]$AllowLargeSemanticValidation,

    [Parameter(Mandatory = $false)]
    [ValidateRange(100000, 50000000)]
    [int]$SemanticValidationRowLimit = 1000000,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 60)]
    [int]$PollIntervalSeconds = 5
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'helpers\TestScriptSupport.ps1')

if (-not $IsWindows) {
    throw 'tests/Measure-StressRun.ps1 currently supports Windows only because it relies on Win32 CIM classes for process and memory sampling.'
}

function Get-StressReportObject {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string[]]$Command,

        [Parameter(Mandatory = $true)]
        [bool]$Validate,

        [Parameter(Mandatory = $true)]
        [string]$ValidationMode,

        [Parameter(Mandatory = $true)]
        [bool]$AllowLargeSemanticValidation,

        [Parameter(Mandatory = $true)]
        [int]$SemanticValidationRowLimit,

        [Parameter(Mandatory = $true)]
        [string]$ResolvedDashboardPath,

        [Parameter(Mandatory = $true)]
        [string]$StdoutPath,

        [Parameter(Mandatory = $true)]
        [string]$StderrPath,

        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Stopwatch]$Stopwatch,

        [Parameter(Mandatory = $true)]
        [int64]$PeakRssBytes,

        [Parameter(Mandatory = $true)]
        [double]$PeakRssAt,

        [Parameter(Mandatory = $true)]
        [int64]$PeakPrivateBytes,

        [Parameter(Mandatory = $true)]
        [double]$PeakPrivateAt,

        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[object]]$Samples,

        [Parameter(Mandatory = $true)]
        [bool]$ChildExited,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [int]$ReturnCode
    )

    return [PSCustomObject]@{
        name = $Name
        report_state = if ($ChildExited) { 'completed' } else { 'running' }
        command = $Command
        validation = [PSCustomObject]@{
            validate = $Validate
            validationMode = if ($Validate) { $ValidationMode } else { 'none' }
            allowLargeSemanticValidation = $AllowLargeSemanticValidation
            semanticValidationRowLimit = $SemanticValidationRowLimit
        }
        dashboard_output_path = $ResolvedDashboardPath
        stdout_path = $StdoutPath
        stderr_path = $StderrPath
        elapsed_seconds = [math]::Round($Stopwatch.Elapsed.TotalSeconds, 2)
        return_code = if ($ChildExited) { $ReturnCode } else { $null }
        peak_tree_rss_bytes = $PeakRssBytes
        peak_tree_rss_gb = [math]::Round(($PeakRssBytes / 1GB), 3)
        peak_tree_rss_at_seconds = $PeakRssAt
        peak_tree_private_bytes = $PeakPrivateBytes
        peak_tree_private_gb = [math]::Round(($PeakPrivateBytes / 1GB), 3)
        peak_tree_private_at_seconds = $PeakPrivateAt
        sample_count = $Samples.Count
        dashboard_exists = (Test-Path -LiteralPath $ResolvedDashboardPath -PathType Leaf)
        dashboard_bytes = if (Test-Path -LiteralPath $ResolvedDashboardPath -PathType Leaf) { (Get-Item -LiteralPath $ResolvedDashboardPath).Length } else { 0 }
        samples = @($Samples)
    }
}

function Write-StressReportFile {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ReportPath,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$Report
    )

    $reportDirectory = Split-Path -Path $ReportPath -Parent
    if (-not [string]::IsNullOrWhiteSpace($reportDirectory) -and -not (Test-Path -LiteralPath $reportDirectory -PathType Container)) {
        [void](New-Item -Path $reportDirectory -ItemType Directory -Force)
    }

    $tempReportPath = $ReportPath + '.tmp'
    $Report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $tempReportPath -Encoding utf8
    Move-Item -LiteralPath $tempReportPath -Destination $ReportPath -Force
    return $Report
}

function Write-StressHeartbeat {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Stopwatch]$Stopwatch,

        [Parameter(Mandatory = $false)]
        [System.Collections.Generic.List[object]]$Samples,

        [Parameter(Mandatory = $true)]
        [string]$StdoutPath,

        [Parameter(Mandatory = $true)]
        [string]$DashboardPath,

        [Parameter(Mandatory = $true)]
        [int64]$PeakRssBytes,

        [Parameter(Mandatory = $true)]
        [int64]$PeakPrivateBytes
    )

    $lastSample = if ($null -ne $Samples -and $Samples.Count -gt 0) { $Samples[$Samples.Count - 1] } else { $null }
    $stdoutStatus = Get-HeartbeatFileStatus -Path $StdoutPath
    $availableMemory = if ($null -ne $lastSample) { [double]$lastSample.available_memory_gb } else { Get-AvailableMemoryGB }
    $stdoutAgeText = if ($null -ne $stdoutStatus.ageSeconds) { ('{0:N1}s' -f $stdoutStatus.ageSeconds) } else { 'n/a' }

    $message = "[{0}] Stress heartbeat ({1}): elapsed={2} peak-rss={3}GB peak-private={4}GB available={5}GB dashboard-exists={6} stdout-bytes={7} stdout-age={8}" -f @(
        (Get-HeartbeatTimestampText)
        $Name
        $Stopwatch.Elapsed.ToString('hh\:mm\:ss')
        [math]::Round(($PeakRssBytes / 1GB), 3)
        [math]::Round(($PeakPrivateBytes / 1GB), 3)
        $availableMemory
        (Test-Path -LiteralPath $DashboardPath -PathType Leaf)
        $stdoutStatus.bytes
        $stdoutAgeText
    )
    Write-Output $message
}

function Get-ProcessTree {
    [CmdletBinding()]
    [OutputType([System.Diagnostics.Process[]])]
    param(
        [Parameter(Mandatory = $true)]
        [int]$RootProcessId
    )

    $processById = @{}
    foreach ($proc in @(Get-Process -ErrorAction SilentlyContinue)) {
        $processById[$proc.Id] = $proc
    }

    $childrenByParent = @{}
    foreach ($proc in @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) {
        $parentId = [int]$proc.ParentProcessId
        if (-not $childrenByParent.ContainsKey($parentId)) {
            $childrenByParent[$parentId] = [System.Collections.Generic.List[int]]::new()
        }
        $childrenByParent[$parentId].Add([int]$proc.ProcessId)
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
            $processes.Add($processById[$processId])
        }
    }

    return @($processes | Sort-Object Id)
}

$repoRoot = Split-Path -Path $PSScriptRoot -Parent
$validationScript = Join-Path $PSScriptRoot 'Invoke-LargeDatasetValidation.ps1'
$resolvedSyntheticPath = [System.IO.Path]::GetFullPath($SyntheticOutputPath)
$resolvedDashboardPath = [System.IO.Path]::GetFullPath($DashboardOutputPath)
$reportPath = if ([string]::IsNullOrWhiteSpace($ReportOutputPath)) {
    Join-Path (Split-Path -Path $resolvedDashboardPath -Parent) ($Name + '.json')
}
else {
    [System.IO.Path]::GetFullPath($ReportOutputPath)
}
$reportDirectory = Split-Path -Path $reportPath -Parent

if (-not (Test-Path -LiteralPath $resolvedSyntheticPath -PathType Container)) {
    throw "Synthetic dataset path '$resolvedSyntheticPath' was not found."
}

if (-not [string]::IsNullOrWhiteSpace($reportDirectory) -and -not (Test-Path -LiteralPath $reportDirectory -PathType Container)) {
    [void](New-Item -Path $reportDirectory -ItemType Directory -Force)
}

if ($ClearDashboardCache) {
    $cachePath = Join-Path $resolvedSyntheticPath '.dashboard-cache'
    if (Test-Path -LiteralPath $cachePath) {
        Remove-Item -LiteralPath $cachePath -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$stdoutPath = Join-Path (Split-Path -Path $reportPath -Parent) ($Name + '.stdout.log')
$stderrPath = Join-Path (Split-Path -Path $reportPath -Parent) ($Name + '.stderr.log')
$command = @(
    'pwsh'
    '-NoProfile'
    '-File'
    $validationScript
    '-SkipSyntheticGeneration'
    '-SyntheticOutputPath'
    $resolvedSyntheticPath
    '-DashboardOutputPath'
    $resolvedDashboardPath
)
if ($Validate) {
    $command += '-Validate'
    $command += '-ValidationMode'
    $command += $ValidationMode
    $command += '-SemanticValidationRowLimit'
    $command += [string]$SemanticValidationRowLimit
    if ($AllowLargeSemanticValidation) {
        $command += '-AllowLargeSemanticValidation'
    }
}

Write-Output ("Benchmarking {0}..." -f $Name)
Write-Output ("  Dataset: {0}" -f $resolvedSyntheticPath)
Write-Output ("  Dashboard: {0}" -f $resolvedDashboardPath)
Write-Output ("  Clear cache: {0}" -f ($ClearDashboardCache -eq $true))
Write-Output ("  Validate: {0}" -f ($Validate -eq $true))
if ($Validate) {
    Write-Output ("  Validation mode: {0}" -f $ValidationMode)
}

$process = Start-Process -FilePath $command[0] `
    -ArgumentList $command[1..($command.Count - 1)] `
    -WorkingDirectory $repoRoot `
    -RedirectStandardOutput $stdoutPath `
    -RedirectStandardError $stderrPath `
    -PassThru

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$samples = [System.Collections.Generic.List[object]]::new()
$peakRssBytes = 0L
$peakRssAt = 0.0
$peakPrivateBytes = 0L
$peakPrivateAt = 0.0

function Add-MeasurementSample {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
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

    if ($null -eq $Samples) {
        return
    }

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

Add-MeasurementSample -Samples $samples -Process $process -Stopwatch $stopwatch -PeakRssBytes ([ref]$peakRssBytes) -PeakRssAt ([ref]$peakRssAt) -PeakPrivateBytes ([ref]$peakPrivateBytes) -PeakPrivateAt ([ref]$peakPrivateAt)
$report = Write-StressReportFile -ReportPath $reportPath -Report (Get-StressReportObject -Name $Name -Command $command -Validate ($Validate -eq $true) -ValidationMode $ValidationMode -AllowLargeSemanticValidation ($AllowLargeSemanticValidation -eq $true) -SemanticValidationRowLimit $SemanticValidationRowLimit -ResolvedDashboardPath $resolvedDashboardPath -StdoutPath $stdoutPath -StderrPath $stderrPath -Stopwatch $stopwatch -PeakRssBytes $peakRssBytes -PeakRssAt $peakRssAt -PeakPrivateBytes $peakPrivateBytes -PeakPrivateAt $peakPrivateAt -Samples $samples -ChildExited $false)
Write-StressHeartbeat -Name $Name -Stopwatch $stopwatch -Samples $samples -StdoutPath $stdoutPath -DashboardPath $resolvedDashboardPath -PeakRssBytes $peakRssBytes -PeakPrivateBytes $peakPrivateBytes

while (-not $process.HasExited) {
    Start-Sleep -Seconds $PollIntervalSeconds
    $process.Refresh()
    Add-MeasurementSample -Samples $samples -Process $process -Stopwatch $stopwatch -PeakRssBytes ([ref]$peakRssBytes) -PeakRssAt ([ref]$peakRssAt) -PeakPrivateBytes ([ref]$peakPrivateBytes) -PeakPrivateAt ([ref]$peakPrivateAt)
    $report = Write-StressReportFile -ReportPath $reportPath -Report (Get-StressReportObject -Name $Name -Command $command -Validate ($Validate -eq $true) -ValidationMode $ValidationMode -AllowLargeSemanticValidation ($AllowLargeSemanticValidation -eq $true) -SemanticValidationRowLimit $SemanticValidationRowLimit -ResolvedDashboardPath $resolvedDashboardPath -StdoutPath $stdoutPath -StderrPath $stderrPath -Stopwatch $stopwatch -PeakRssBytes $peakRssBytes -PeakRssAt $peakRssAt -PeakPrivateBytes $peakPrivateBytes -PeakPrivateAt $peakPrivateAt -Samples $samples -ChildExited $false)
    if (-not $process.HasExited) {
        Write-StressHeartbeat -Name $Name -Stopwatch $stopwatch -Samples $samples -StdoutPath $stdoutPath -DashboardPath $resolvedDashboardPath -PeakRssBytes $peakRssBytes -PeakPrivateBytes $peakPrivateBytes
    }
}

$process.WaitForExit()
$process.Refresh()
Add-MeasurementSample -Samples $samples -Process $process -Stopwatch $stopwatch -PeakRssBytes ([ref]$peakRssBytes) -PeakRssAt ([ref]$peakRssAt) -PeakPrivateBytes ([ref]$peakPrivateBytes) -PeakPrivateAt ([ref]$peakPrivateAt)
$stopwatch.Stop()

$report = Write-StressReportFile -ReportPath $reportPath -Report (Get-StressReportObject -Name $Name -Command $command -Validate ($Validate -eq $true) -ValidationMode $ValidationMode -AllowLargeSemanticValidation ($AllowLargeSemanticValidation -eq $true) -SemanticValidationRowLimit $SemanticValidationRowLimit -ResolvedDashboardPath $resolvedDashboardPath -StdoutPath $stdoutPath -StderrPath $stderrPath -Stopwatch $stopwatch -PeakRssBytes $peakRssBytes -PeakRssAt $peakRssAt -PeakPrivateBytes $peakPrivateBytes -PeakPrivateAt $peakPrivateAt -Samples $samples -ChildExited $true -ReturnCode $process.ExitCode)

Write-Output ("  Elapsed seconds: {0}" -f $report.elapsed_seconds)
Write-Output ("  Peak RSS GB: {0}" -f $report.peak_tree_rss_gb)
Write-Output ("  Peak Private GB: {0}" -f $report.peak_tree_private_gb)
Write-Output ("  Report: {0}" -f $reportPath)

if ($process.ExitCode -ne 0) {
    throw "Benchmark child process exited with code $($process.ExitCode)."
}
