#Requires -Version 7.6
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Executable,
    [string[]]$Arguments = @()
)
$ErrorActionPreference = 'Stop'
try {
    if (-not $IsWindows -or ('LaunchBound.OuterBrowserSupervisor' -as [type]) -or ('LaunchBound.JobOwner' -as [type])) {
        throw 'Supervisor initialization failed.'
    }
    Add-Type -Path @(
        (Join-Path $PSScriptRoot 'helpers\LaunchBoundJob.cs'),
        (Join-Path $PSScriptRoot 'helpers\OuterBrowserSupervisor.cs')
    )
    $result = [LaunchBound.OuterBrowserSupervisor]::Run($Executable, $Arguments)
    [Console]::Error.WriteLine(($result | ConvertTo-Json -Compress -Depth 4))
    if ($result.Success) { exit 0 }
}
catch { [Console]::Error.WriteLine('Outer supervisor: failed; cleanup may be unconfirmed.') }
exit 1
