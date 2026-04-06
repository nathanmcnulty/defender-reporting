# Azure Functions profile - loaded on every cold start.
# Managed dependencies are not supported on Flex Consumption; Az.Accounts is
# bundled in the Modules/ directory by Build-FunctionApp.ps1.

$traceEnabled = ($env:PIPELINE_FILE_TRACE_ENABLED -eq 'true')
$tracePath = $null

function Write-ProfileTraceLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if (-not $traceEnabled) {
        return
    }

    try {
        if (-not $tracePath) {
            if (-not [string]::IsNullOrWhiteSpace($env:TEMP)) {
                $diagnosticsRoot = Join-Path -Path $env:TEMP -ChildPath 'FunctionsData'
            }
            elseif (-not [string]::IsNullOrWhiteSpace($env:HOME)) {
                $diagnosticsRoot = Join-Path -Path $env:HOME -ChildPath 'site/diagnostics'
            }
            else {
                return
            }

            New-Item -Path $diagnosticsRoot -ItemType Directory -Force | Out-Null
            $tracePath = Join-Path -Path $diagnosticsRoot -ChildPath 'FunctionProfile.trace.log'
        }

        Add-Content -Path $tracePath -Value ("[{0}] {1}" -f ([datetime]::UtcNow).ToString('o'), $Message)
    }
    catch {
        Write-Verbose ("Profile trace write failed: {0}" -f $_.Exception.Message)
    }
}

$modulesPath = Join-Path -Path $PSScriptRoot -ChildPath 'Modules'
Write-ProfileTraceLine -Message ("profile start; HOME='{0}'; PSScriptRoot='{1}'; modulesPath='{2}'" -f $env:HOME, $PSScriptRoot, $modulesPath)

if (Test-Path -LiteralPath $modulesPath -PathType Container) {
    $pathSeparator = [System.IO.Path]::PathSeparator
    $currentModulePaths = @($env:PSModulePath -split [regex]::Escape([string]$pathSeparator))
    if ($currentModulePaths -notcontains $modulesPath) {
        $env:PSModulePath = $modulesPath + $pathSeparator + $env:PSModulePath
    }

    Write-ProfileTraceLine -Message ("prepended Modules path; PSModulePath='{0}'" -f $env:PSModulePath)
}
else {
    Write-ProfileTraceLine -Message 'Modules directory was not found during profile startup.'
}

if ($env:MSI_SECRET) {
    Disable-AzContextAutosave -Scope Process | Out-Null
    Write-ProfileTraceLine -Message 'Disabled Az context autosave for MSI startup.'
}
