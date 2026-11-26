#Requires -Version 7.6
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'Windows required.' }
Add-Type -Path @(
    (Join-Path $PSScriptRoot 'helpers\LaunchBoundJob.cs'),
    (Join-Path $PSScriptRoot 'helpers\OuterBrowserSupervisor.cs'),
    (Join-Path $PSScriptRoot 'helpers\OuterBrowserSupervisorTests.cs')
)
[OuterSupervisorTests.Tests]::Contracts()
$directory = Join-Path $PSScriptRoot ("..\.local\outer-supervisor-regression-" + [guid]::NewGuid().ToString('N'))
if (Test-Path -LiteralPath $directory) { throw 'Regression destination already exists.' }
[void](New-Item -ItemType Directory -Path $directory -Force)
try {
    [OuterSupervisorTests.Tests]::Native([Environment]::ProcessPath, (Join-Path $directory 'marker'))
    [OuterSupervisorTests.Tests]::ChildSurvival([Environment]::ProcessPath, (Join-Path $directory 'child'))
    [OuterSupervisorTests.Tests]::InnerCompatibility([Environment]::ProcessPath, (Join-Path $PSScriptRoot 'helpers\OuterBrowserInnerFixture.ps1'), (Join-Path $directory 'profile'), (Join-Path $directory 'inner'))
    [OuterSupervisorTests.Tests]::Watchdog([Environment]::ProcessPath, (Join-Path $directory 'watchdog'))
}
finally {
    foreach ($name in @('marker', 'child', 'inner', 'watchdog')) {
        $file = Join-Path $directory $name
        if (Test-Path -LiteralPath $file -PathType Leaf) { Remove-Item -LiteralPath $file -Force }
    }
    Remove-Item -LiteralPath $directory -Force
}
Write-Output 'Outer browser supervisor regression passed.'
