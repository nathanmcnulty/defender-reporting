#Requires -Version 7.6
# One fixed owner launch. No protocol requests are parsed or forwarded here.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false,$true)
Add-Type -Path @((Join-Path $PSScriptRoot 'LaunchBoundJob.cs'),(Join-Path $PSScriptRoot 'LaunchBoundOwnerBridge.cs'))
$code=[LaunchBound.OwnerBridge]::Run((Join-Path $PSScriptRoot 'Invoke-LaunchBoundOwner.ps1'))
exit $code
