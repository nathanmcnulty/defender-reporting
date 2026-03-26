#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$FilePath,

    [Parameter(Mandatory = $false)]
    [string[]]$ArgumentList = @(),

    [Parameter(Mandatory = $false)]
    [string]$WorkingDirectory = (Get-Location).Path,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 64)]
    [int]$MinimumAvailableMemoryGB = 4,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 60)]
    [int]$PollIntervalSeconds = 5
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-AvailableMemoryGB {
    [CmdletBinding()]
    [OutputType([double])]
    param()

    $os = Get-CimInstance Win32_OperatingSystem
    return [math]::Round(($os.FreePhysicalMemory / 1MB), 2)
}

function Get-ProcessTree {
    [CmdletBinding()]
    [OutputType([System.Diagnostics.Process[]])]
    param(
        [Parameter(Mandatory = $true)]
        [int]$RootProcessId
    )

    $liveProcesses = @{}
    foreach ($proc in @(Get-Process -ErrorAction SilentlyContinue)) {
        $liveProcesses[$proc.Id] = $proc
    }

    $childrenByParentId = @{}
    foreach ($proc in @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) {
        $parentId = [int]$proc.ParentProcessId
        if (-not $childrenByParentId.ContainsKey($parentId)) {
            $childrenByParentId[$parentId] = [System.Collections.Generic.List[int]]::new()
        }
        $childrenByParentId[$parentId].Add([int]$proc.ProcessId)
    }

    $processIds = [System.Collections.Generic.HashSet[int]]::new()
    $pending = [System.Collections.Generic.Queue[int]]::new()
    $pending.Enqueue($RootProcessId)

    while ($pending.Count -gt 0) {
        $processId = $pending.Dequeue()
        if (-not $processIds.Add($processId)) {
            continue
        }

        if ($childrenByParentId.ContainsKey($processId)) {
            foreach ($childProcessId in $childrenByParentId[$processId]) {
                $pending.Enqueue($childProcessId)
            }
        }
    }

    $processes = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()
    foreach ($processId in $processIds) {
        if ($liveProcesses.ContainsKey($processId)) {
            $processes.Add($liveProcesses[$processId])
        }
    }

    return @($processes | Sort-Object Id)
}

function Stop-ProcessTree {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$RootProcessId
    )

    $processTree = @(Get-ProcessTree -RootProcessId $RootProcessId | Sort-Object Id -Descending)
    foreach ($proc in $processTree) {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    }
}

function Write-LogTail {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Label,

        [Parameter(Mandatory = $false)]
        [int]$TailLineCount = 200
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

$resolvedFilePath = [System.IO.Path]::GetFullPath((Join-Path $WorkingDirectory $FilePath))
if (-not (Test-Path -LiteralPath $resolvedFilePath -PathType Leaf)) {
    throw "File '$resolvedFilePath' was not found."
}

$stdoutPath = Join-Path ([System.IO.Path]::GetTempPath()) ('pwsh-guard-stdout-' + [guid]::NewGuid().ToString('N') + '.log')
$stderrPath = Join-Path ([System.IO.Path]::GetTempPath()) ('pwsh-guard-stderr-' + [guid]::NewGuid().ToString('N') + '.log')
$pwshArgs = @('-NoProfile', '-File', $resolvedFilePath) + @($ArgumentList)

Write-Output ("Starting guarded PowerShell process: {0}" -f $resolvedFilePath)
Write-Output ("Working directory: {0}" -f $WorkingDirectory)
Write-Output ("Minimum available memory threshold: {0} GB" -f $MinimumAvailableMemoryGB)

$process = Start-Process -FilePath 'pwsh' `
    -ArgumentList $pwshArgs `
    -WorkingDirectory $WorkingDirectory `
    -RedirectStandardOutput $stdoutPath `
    -RedirectStandardError $stderrPath `
    -PassThru

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$terminatedByGuard = $false

try {
    while (-not $process.HasExited) {
        Start-Sleep -Seconds $PollIntervalSeconds
        $process.Refresh()
        if ($process.HasExited) {
            break
        }

        $availableMemoryGB = Get-AvailableMemoryGB
        $processTree = @(Get-ProcessTree -RootProcessId $process.Id)
        $treeWorkingSetBytes = 0
        if ($processTree.Count -gt 0) {
            $treeWorkingSetBytes = ($processTree | Measure-Object -Property WorkingSet64 -Sum).Sum
        }
        $treeWorkingSetGB = [math]::Round(($treeWorkingSetBytes / 1GB), 2)
        $pwshProcessCount = @($processTree | Where-Object { $_.ProcessName -eq 'pwsh' }).Count
        $largestProcess = $processTree | Sort-Object WorkingSet64 -Descending | Select-Object -First 1
        $largestProcessSummary = if ($largestProcess) {
            '{0}#{1}:{2}GB' -f $largestProcess.ProcessName, $largestProcess.Id, [math]::Round(($largestProcess.WorkingSet64 / 1GB), 2)
        }
        else {
            'n/a'
        }
        Write-Output ("Guard status: elapsed={0} tree-procs={1} pwsh={2} tree-ws={3} GB largest={4} available={5} GB" -f $stopwatch.Elapsed.ToString('hh\:mm\:ss'), $processTree.Count, $pwshProcessCount, $treeWorkingSetGB, $largestProcessSummary, $availableMemoryGB)

        if ($availableMemoryGB -le $MinimumAvailableMemoryGB) {
            $processIds = if ($processTree.Count -gt 0) { ($processTree | ForEach-Object { $_.Id }) -join ', ' } else { [string]$process.Id }
            Write-Warning ("Available system memory dropped to {0} GB. Terminating process tree rooted at pwsh {1}. PIDs: {2}" -f $availableMemoryGB, $process.Id, $processIds)
            Stop-ProcessTree -RootProcessId $process.Id
            $terminatedByGuard = $true
            break
        }
    }

    $process.WaitForExit()
    Start-Sleep -Seconds 2

    $remainingDescendants = @(Get-ProcessTree -RootProcessId $process.Id | Where-Object { $_.Id -ne $process.Id })
    if ($remainingDescendants.Count -gt 0) {
        $remainingIds = ($remainingDescendants | ForEach-Object { $_.Id }) -join ', '
        Write-Warning ("Root pwsh process {0} exited but left descendant process(es) running. Terminating PIDs: {1}" -f $process.Id, $remainingIds)
        Stop-ProcessTree -RootProcessId $process.Id
        $terminatedByGuard = $true
    }
}
finally {
    $stopwatch.Stop()
}

Write-LogTail -Path $stdoutPath -Label 'Child stdout'
Write-LogTail -Path $stderrPath -Label 'Child stderr'

Write-Output ''
Write-Output ("Guarded process exit code: {0}" -f $process.ExitCode)
Write-Output ("Elapsed seconds: {0}" -f [math]::Round($stopwatch.Elapsed.TotalSeconds, 2))

if (Test-Path -LiteralPath $stdoutPath -PathType Leaf) {
    Remove-Item -LiteralPath $stdoutPath -Force -ErrorAction SilentlyContinue
}
if (Test-Path -LiteralPath $stderrPath -PathType Leaf) {
    Remove-Item -LiteralPath $stderrPath -Force -ErrorAction SilentlyContinue
}

if ($terminatedByGuard) {
    throw "The child PowerShell process was terminated by the memory guard after available system memory fell below ${MinimumAvailableMemoryGB}GB."
}

if ($process.ExitCode -ne 0) {
    throw "The child PowerShell process exited with code $($process.ExitCode)."
}
