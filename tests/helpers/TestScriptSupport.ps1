# Shared helper surface for benchmark and validation scripts under tests\.

function Get-AvailableMemoryGB {
    [CmdletBinding()]
    [OutputType([double])]
    param()

    if (-not $IsWindows) {
        return [double]::NaN
    }

    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
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

function ConvertTo-UtcDateTime {
    [CmdletBinding()]
    [OutputType([datetime])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [datetime]) {
        return ([datetime]$Value).ToUniversalTime()
    }

    if ($Value -is [datetimeoffset]) {
        return ([datetimeoffset]$Value).UtcDateTime
    }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }

    $parsed = [datetimeoffset]::MinValue
    if ([datetimeoffset]::TryParse($text, [ref]$parsed)) {
        return $parsed.UtcDateTime
    }

    return $null
}

function Get-ObjectPropertyValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function Test-ScriptParameterSupport {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath,

        [Parameter(Mandatory = $true)]
        [string]$ParameterName
    )

    if (-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)) {
        return $false
    }

    try {
        $command = Get-Command -Name $ScriptPath -ErrorAction Stop
        return $command.Parameters.ContainsKey($ParameterName)
    }
    catch {
        Write-Verbose ("Unable to inspect parameters for {0}: {1}" -f $ScriptPath, $_.Exception.Message)
        return $false
    }
}

function Invoke-GitText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoPath,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    if (-not (Test-Path -LiteralPath $RepoPath -PathType Container)) {
        return $null
    }

    $output = (& git -C $RepoPath @Arguments 2>$null | Out-String)
    if ($LASTEXITCODE -ne 0) {
        return $null
    }

    $trimmed = $output.Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed)) {
        return $null
    }

    return $trimmed
}

function Add-PathSuffixBeforeExtensionLocal {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Suffix
    )

    $extension = [System.IO.Path]::GetExtension($Path)
    if ([string]::IsNullOrEmpty($extension)) {
        return ($Path + $Suffix)
    }

    return ($Path.Substring(0, $Path.Length - $extension.Length) + $Suffix + $extension)
}

function Get-DiagnosticPhaseTimingSummary {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }

    $phaseByName = [ordered]@{}
    $pipelineStartUtc = $null
    $pipelineEndUtc = $null

    foreach ($line in Get-Content -LiteralPath $Path) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        $parts = @([string]$line -split "`t")
        if ($parts.Count -lt 3) {
            continue
        }

        $timestampUtc = ConvertTo-UtcDateTime -Value $parts[0]
        if ($null -eq $timestampUtc) {
            continue
        }

        $eventType = [string]$parts[1]
        $name = [string]$parts[2]
        $status = if ($parts.Count -ge 4) { [string]$parts[3] } else { $null }

        switch ($eventType) {
            'pipeline-start' {
                if ($null -eq $pipelineStartUtc) {
                    $pipelineStartUtc = $timestampUtc
                }
            }
            'pipeline-end' {
                $pipelineEndUtc = $timestampUtc
            }
            'phase-start' {
                if (-not $phaseByName.Contains($name)) {
                    $phaseByName[$name] = [ordered]@{
                        name = $name
                        start_utc = $null
                        end_utc = $null
                        status = $null
                    }
                }

                if ($null -eq $phaseByName[$name].start_utc) {
                    $phaseByName[$name].start_utc = $timestampUtc
                }
            }
            'phase-end' {
                if (-not $phaseByName.Contains($name)) {
                    $phaseByName[$name] = [ordered]@{
                        name = $name
                        start_utc = $null
                        end_utc = $null
                        status = $null
                    }
                }

                $phaseByName[$name].end_utc = $timestampUtc
                $phaseByName[$name].status = $status
            }
        }
    }

    $phaseSummaries = @(
        foreach ($phaseEntry in $phaseByName.Values) {
            $elapsedSeconds = if ($null -ne $phaseEntry.start_utc -and $null -ne $phaseEntry.end_utc) {
                [math]::Round((New-TimeSpan -Start $phaseEntry.start_utc -End $phaseEntry.end_utc).TotalSeconds, 2)
            }
            else {
                $null
            }

            [PSCustomObject]@{
                name = [string]$phaseEntry.name
                status = if ([string]::IsNullOrWhiteSpace([string]$phaseEntry.status)) { 'unknown' } else { [string]$phaseEntry.status }
                elapsedSeconds = $elapsedSeconds
            }
        }
    )

    return [PSCustomObject]@{
        path = $Path
        phase_summaries = $phaseSummaries
        pipeline_elapsed_seconds = if ($null -ne $pipelineStartUtc -and $null -ne $pipelineEndUtc) {
            [math]::Round((New-TimeSpan -Start $pipelineStartUtc -End $pipelineEndUtc).TotalSeconds, 2)
        }
        else {
            $null
        }
    }
}
