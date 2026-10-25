function Initialize-LaunchBoundOwner {
    [CmdletBinding()]
    param()
    if (-not ('LaunchBound.JobOwner' -as [type])) { Add-Type -Path (Join-Path $PSScriptRoot 'LaunchBoundJob.cs') }
}

function New-LaunchBoundAttempt {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Creates managed attempt state only; native launch occurs in the explicit capture operation.')]
    [CmdletBinding()]
    param([string]$ProfilePath)
    Initialize-LaunchBoundOwner
    $id = [guid]::NewGuid().ToString('N')
    $owner = [LaunchBound.JobOwner]::new($id, $ProfilePath)
    [pscustomobject]@{ Owner = $owner; RunId = $id; ProfilePath = $ProfilePath; ProfileKey = $owner.ProfileKey; Failed = $false; Confirmed = $false; Receipt = $null; NativeErrorCode = $null }
}

function Assert-LaunchBoundProfileContained {
    [CmdletBinding()]
    param([object]$Owner, [string]$ProfilePath)
    # A diagnostic only: no PID returned here is ever termination authority.
    Initialize-HostedSmokeCapture
    foreach ($item in @(Get-CimInstance Win32_Process -Property ProcessId,CommandLine,CreationDate -ErrorAction Stop)) {
        if (-not $item.CommandLine -or -not [HostedSmoke.Capture]::OwnsProfile($item.CommandLine, $ProfilePath)) { continue }
        try { $member = $Owner.Contains([int]$item.ProcessId) }
        catch {
            $fresh = @(Get-CimInstance Win32_Process -Filter "ProcessId=$($item.ProcessId)" -Property ProcessId,CommandLine,CreationDate -ErrorAction Stop)
            if ($fresh.Count -eq 0) { continue }
            throw 'Profile membership unknown.'
        }
        if (-not $member) {
            $fresh = @(Get-CimInstance Win32_Process -Filter "ProcessId=$($item.ProcessId)" -Property ProcessId,CommandLine,CreationDate -ErrorAction Stop)
            if ($fresh.Count -eq 0) { continue }
            if ($fresh.Count -eq 1 -and $item.CreationDate -is [datetime] -and $fresh[0].CreationDate -is [datetime] -and $item.CreationDate -ne $fresh[0].CreationDate -and -not [HostedSmoke.Capture]::OwnsProfile($fresh[0].CommandLine, $ProfilePath)) { continue }
            throw 'Exact profile found outside owned job.'
        }
    }
}

function Invoke-LaunchBoundCapture {
    [CmdletBinding()]
    param([object]$Attempt, [string]$Executable, [string[]]$Arguments, [int]$WaitMilliseconds)
    try {
        $result = $Attempt.Owner.RunCaptured($Executable, $Arguments, $Attempt.ProfilePath, $WaitMilliseconds)
        Assert-LaunchBoundProfileContained -Owner $Attempt.Owner -ProfilePath $Attempt.ProfilePath
        $Attempt.Receipt = $result.Completion
        return $result
    }
    catch {
        $Attempt.Failed = $true
        $cause = $_.Exception.GetBaseException()
        if ($cause -is [ComponentModel.Win32Exception]) { $Attempt.NativeErrorCode = $cause.NativeErrorCode }
        throw
    }
}

function Complete-LaunchBoundAttempt {
    [CmdletBinding()]
    param([object]$Attempt)
    try {
        $clock = [Diagnostics.Stopwatch]::StartNew()
        $proof = $Attempt.Owner.Stop(5000)
        Assert-LaunchBoundProfileContained -Owner $Attempt.Owner -ProfilePath $Attempt.ProfilePath
        if ($clock.ElapsedMilliseconds -ge 5000) { throw 'Late completion proof.' }
        $valid = -not $Attempt.Failed -and $proof.RunId -ceq $Attempt.RunId -and $proof.ProfileKey -ceq $Attempt.ProfileKey -and $proof.Created -and $proof.Assigned -and $proof.Resumed -and $proof.Sealed -and $proof.Terminal -and $proof.Confirmed -and $proof.StreamsComplete -and $proof.ActiveProcesses -eq 0 -and $proof.Pids.Length -eq 0
        if (-not $valid) { throw 'Launch completion unknown.' }
        $Attempt.Receipt = $proof
        $Attempt.Confirmed = $true
        [pscustomobject]@{ Confirmed = $true; Failures = @(); Diagnostics = @('launch-bound-job-zero') }
    }
    catch {
        $Attempt.Failed = $true
        $Attempt.Confirmed = $false
        [pscustomobject]@{ Confirmed = $false; Failures = @('launch-bound-completion-unknown'); Diagnostics = @() }
    }
}

function Get-LaunchBoundAttemptEvidence {
    [CmdletBinding()]
    param([object]$Attempt)
    $setup = if ($Attempt.Owner.PSObject.Properties['Setup']) { $Attempt.Owner.Setup } else { $null }
    [pscustomobject]@{
        created = $null -ne $setup -and $setup.Created
        assigned = $null -ne $setup -and $setup.Assigned
        resumed = $null -ne $setup -and $setup.Resumed
        assignmentSealed = $null -ne $setup -and $setup.Sealed
        confirmed = [bool]$Attempt.Confirmed
        failed = [bool]$Attempt.Failed
        activeProcesses = $(if ($Attempt.Confirmed -and $null -ne $Attempt.Receipt) { $Attempt.Receipt.ActiveProcesses } else { $null })
        streamsComplete = $null -ne $Attempt.Receipt -and $Attempt.Receipt.StreamsComplete
        forced = $null -ne $Attempt.Receipt -and $Attempt.Receipt.PSObject.Properties['Forced'] -and $Attempt.Receipt.Forced
        nativeErrorCode = $(if ($Attempt.PSObject.Properties['NativeErrorCode'] -and $null -ne $Attempt.NativeErrorCode -and $Attempt.NativeErrorCode -ge 0 -and $Attempt.NativeErrorCode -le 65535) { $Attempt.NativeErrorCode } else { $null })
    }
}
